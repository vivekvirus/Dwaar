package app.dwaar.guard

import android.app.Application
import app.dwaar.guard.sync.SyncScheduler

class GuardApplication : Application() {
    val container: AppContainer by lazy { AppContainer(this) }

    override fun onCreate() {
        super.onCreate()
        SyncScheduler.schedulePeriodic(this)
    }
}
