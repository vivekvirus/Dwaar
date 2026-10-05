package app.dwaar.guard.data

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.sqlite.db.SupportSQLiteDatabase

@Entity(tableName = "outbox_events", indices = [Index(value = ["eventId"], unique = true), Index("state", "nextAttemptAtMs")])
data class OutboxEventEntity(
    @PrimaryKey val seq: Long,
    val eventId: String,
    val type: String,
    val entityId: String,
    /** Full signed wire JSON, written once; retries re-send exactly this text. */
    val canonicalJson: String,
    val state: String,
    val attempts: Int,
    val nextAttemptAtMs: Long,
    val lastError: String?,
)

/** Single-row monotonic device sequence. Survives pruning of acknowledged events. */
@Entity(tableName = "device_counter")
data class DeviceCounterEntity(@PrimaryKey val id: Int = 1, val lastSeq: Long)

@Entity(tableName = "local_visits")
data class LocalVisitEntity(
    @PrimaryKey val entityId: String,
    val requestId: String?,
    val entry: String,
    val entryEventId: String?,
    val entryRecordedAtMs: Long?,
)

/** Cached directory entities (tower-first grid) so the destination grid renders offline. Never a resident name or number (GATE-13). */
@Entity(tableName = "cached_units")
data class CachedUnitEntity(
    @PrimaryKey val unitId: String,
    val tower: String,
    val label: String,
    val surnameMasked: String?,
    val cachedAtMs: Long,
)

@Dao
interface OutboxDao {
    @Query("SELECT lastSeq FROM device_counter WHERE id = 1") suspend fun lastSeq(): Long?
    @Insert(onConflict = OnConflictStrategy.REPLACE) suspend fun putCounter(c: DeviceCounterEntity)
    @Insert(onConflict = OnConflictStrategy.ABORT) suspend fun insert(e: OutboxEventEntity)
    @Query("SELECT * FROM outbox_events WHERE state = 'PENDING' AND nextAttemptAtMs <= :now ORDER BY seq LIMIT :limit")
    suspend fun due(now: Long, limit: Int): List<OutboxEventEntity>
    @Query("SELECT COUNT(*) FROM outbox_events WHERE state = 'PENDING'") suspend fun pendingCount(): Int
    @Query("UPDATE outbox_events SET state = 'ACKED', lastError = NULL WHERE eventId IN (:ids)") suspend fun ack(ids: List<String>)
    @Query("UPDATE outbox_events SET state = 'QUARANTINED', lastError = :reason WHERE eventId = :id") suspend fun quarantine(id: String, reason: String)
    @Query("UPDATE outbox_events SET attempts = attempts + 1, nextAttemptAtMs = :next, lastError = :err WHERE eventId IN (:ids) AND state = 'PENDING'")
    suspend fun retry(ids: List<String>, next: Long, err: String?)
    @Query("SELECT * FROM outbox_events ORDER BY seq") suspend fun all(): List<OutboxEventEntity>
    @Insert(onConflict = OnConflictStrategy.REPLACE) suspend fun upsertVisit(v: LocalVisitEntity)
    @Query("SELECT * FROM local_visits WHERE entityId = :id") suspend fun visit(id: String): LocalVisitEntity?
    @Query("UPDATE local_visits SET entry = 'SYNCED' WHERE entryEventId IN (:ids) AND entry = 'SAVED_PENDING_SYNC'") suspend fun markVisitsSynced(ids: List<String>)
}

@Dao
interface UnitCacheDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE) suspend fun putAll(units: List<CachedUnitEntity>)
    @Query("DELETE FROM cached_units") suspend fun clear()
    @Query("SELECT * FROM cached_units ORDER BY tower, label") suspend fun all(): List<CachedUnitEntity>
}

@Database(entities = [OutboxEventEntity::class, DeviceCounterEntity::class, LocalVisitEntity::class, CachedUnitEntity::class], version = 1, exportSchema = true)
abstract class GuardDatabase : RoomDatabase() {
    abstract fun outbox(): OutboxDao
    abstract fun unitCache(): UnitCacheDao

    companion object {
        /** EDGE-01 (partial): WAL + synchronous=FULL. Field-level/at-rest encryption is NOT implemented (ADR-0014 "not verified"). */
        fun open(context: Context, name: String? = "guard.db"): GuardDatabase =
            Room.databaseBuilder(context, GuardDatabase::class.java, name ?: "guard.db")
                .setJournalMode(JournalMode.WRITE_AHEAD_LOGGING)
                .addCallback(object : Callback() {
                    override fun onOpen(db: SupportSQLiteDatabase) { db.query("PRAGMA synchronous=FULL").close() }
                })
                .build()

        fun inMemory(context: Context): GuardDatabase =
            Room.inMemoryDatabaseBuilder(context, GuardDatabase::class.java).allowMainThreadQueries().build()
    }
}
