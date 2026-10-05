package app.dwaar.guard.sync

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.CoroutineWorker
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import app.dwaar.guard.GuardApplication
import app.dwaar.guard.core.edge.SyncRunResult
import java.util.concurrent.TimeUnit

/**
 * WorkManager sync STUB (slice 2). Drains the outbox through [app.dwaar.guard.core.edge.SyncEngine]. With
 * `BuildConfig.SYNC_SIMULATED=true` (default) the target is `SimulatedSyncApi`, which acknowledges everything without any
 * backend: a "synced" result then proves nothing. The real endpoint arrives in slice 3; the HTTP implementation
 * (`HttpGuardApi.postBatch`) exists behind the same interface.
 */
class SyncWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val container = (applicationContext as GuardApplication).container
        return when (val r = container.syncEngine().runOnce()) {
            SyncRunResult.NothingToSend -> Result.success()
            is SyncRunResult.Sent -> { container.onSyncProgress(r); Result.success() }
            is SyncRunResult.WillRetry -> Result.retry()
        }
    }
}

object SyncScheduler {
    private const val PERIODIC = "dwaar-outbox-periodic"
    private const val ONE_SHOT = "dwaar-outbox-now"
    private val online = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

    fun schedulePeriodic(context: Context) {
        val req = PeriodicWorkRequestBuilder<SyncWorker>(15, TimeUnit.MINUTES)
            .setConstraints(online).setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS).build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(PERIODIC, ExistingPeriodicWorkPolicy.KEEP, req)
    }

    /** Called after a local commit; the commit itself never waits for the network (offline-first). */
    fun kick(context: Context) {
        val req = OneTimeWorkRequestBuilder<SyncWorker>().setConstraints(online)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS).build()
        WorkManager.getInstance(context).enqueueUniqueWork(ONE_SHOT, ExistingWorkPolicy.REPLACE, req)
    }
}
