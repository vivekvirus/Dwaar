package app.dwaar.guard.kiosk

import android.app.Activity
import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context

/** Device-admin receiver; becomes device owner only via `adb shell dpm set-device-owner` or QR/zero-touch provisioning. */
class DwaarDeviceAdminReceiver : DeviceAdminReceiver()

enum class KioskState { NOT_DEVICE_OWNER, LOCKED, ALREADY_LOCKED, ERROR }

/**
 * Lock-task (kiosk) support for the guard tablet (D-06). Declared and wired, NOT field-tested: it has never run on a
 * provisioned device in this build (no emulator or hardware here).
 */
object KioskController {
    fun enter(activity: Activity): KioskState {
        return try {
            val dpm = activity.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            if (!dpm.isDeviceOwnerApp(activity.packageName)) return KioskState.NOT_DEVICE_OWNER
            val admin = ComponentName(activity, DwaarDeviceAdminReceiver::class.java)
            dpm.setLockTaskPackages(admin, arrayOf(activity.packageName))
            val am = activity.getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
            if (am.lockTaskModeState != android.app.ActivityManager.LOCK_TASK_MODE_NONE) KioskState.ALREADY_LOCKED
            else { activity.startLockTask(); KioskState.LOCKED }
        } catch (e: SecurityException) {
            KioskState.ERROR
        }
    }

    /** Supervisor-only exit path (to be gated by a PIN in a later slice). */
    fun exit(activity: Activity) { try { activity.stopLockTask() } catch (_: IllegalStateException) {} }
}
