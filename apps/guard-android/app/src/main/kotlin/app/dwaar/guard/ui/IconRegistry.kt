package app.dwaar.guard.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudDone
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Emergency
import androidx.compose.material.icons.filled.EmojiEvents
import androidx.compose.material.icons.filled.Groups
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.HomeWork
import androidx.compose.material.icons.filled.HourglassTop
import androidx.compose.material.icons.filled.HowToReg
import androidx.compose.material.icons.filled.Inventory2
import androidx.compose.material.icons.filled.LocalShipping
import androidx.compose.material.icons.filled.PanTool
import androidx.compose.material.icons.filled.PersonPin
import androidx.compose.material.icons.automirrored.filled.PhoneMissed
import androidx.compose.material.icons.filled.PlayCircle
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.School
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.StopCircle
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.WifiOff
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.automirrored.filled.Assignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.dp

/** Octagon with a cut-out X: the DENY shape. Differs from the ALLOW circle-with-tick in outline, not just colour (UX-02). */
val OctagonX: ImageVector by lazy {
    ImageVector.Builder("OctagonX", 24.dp, 24.dp, 24f, 24f).apply {
        path(fill = SolidColor(Color.Black), pathFillType = PathFillType.EvenOdd) {
            moveTo(8f, 2f); lineTo(16f, 2f); lineTo(22f, 8f); lineTo(22f, 16f); lineTo(16f, 22f); lineTo(8f, 22f); lineTo(2f, 16f); lineTo(2f, 8f); close()
            moveTo(9.2f, 7.8f); lineTo(12f, 10.6f); lineTo(14.8f, 7.8f); lineTo(16.2f, 9.2f); lineTo(13.4f, 12f); lineTo(16.2f, 14.8f)
            lineTo(14.8f, 16.2f); lineTo(12f, 13.4f); lineTo(9.2f, 16.2f); lineTo(7.8f, 14.8f); lineTo(10.6f, 12f); lineTo(7.8f, 9.2f); close()
        }
    }.build()
}

/** icons.yaml icon NAME -> vector. Every name in packages/i18n/icons.yaml must be mapped (unit-tested). */
object IconRegistry {
    val byName: Map<String, ImageVector> = mapOf(
        "person-badge" to Icons.Filled.PersonPin,
        "package-delivery" to Icons.Filled.LocalShipping,
        "wrench" to Icons.Filled.Build,
        "qr-scan" to Icons.Filled.QrCodeScanner,
        "parcel-box" to Icons.Filled.Inventory2,
        "people-inside" to Icons.Filled.Groups,
        "alert-triangle" to Icons.Filled.Warning,
        "clock-shift" to Icons.Filled.Schedule,
        "check-circle" to Icons.Filled.CheckCircle,
        "x-octagon" to OctagonX,
        "wifi-off" to Icons.Filled.WifiOff,
        "wifi" to Icons.Filled.Wifi,
        "shield-clock" to Icons.Filled.Security,
        "shield-alert" to Icons.Filled.GppMaybe,
        "cloud-upload-pending" to Icons.Filled.CloudUpload,
        "cloud-check" to Icons.Filled.CloudDone,
        "device-saved" to Icons.Filled.Save,
        "phone-call" to Icons.Filled.Call,
        "hourglass" to Icons.Filled.HourglassTop,
        "phone-missed" to Icons.AutoMirrored.Filled.PhoneMissed,
        "hand-parcel" to Icons.Filled.PanTool,
        "home-check" to Icons.Filled.HomeWork,
        "person-check" to Icons.Filled.HowToReg,
        "seal-check" to Icons.Filled.Verified,
        "clipboard-alert" to Icons.AutoMirrored.Filled.Assignment,
        "siren" to Icons.Filled.Emergency,
        "play-circle" to Icons.Filled.PlayCircle,
        "stop-circle" to Icons.Filled.StopCircle,
        "graduation-cap" to Icons.Filled.School,
        "award" to Icons.Filled.EmojiEvents,
    )

    fun forName(name: String?): ImageVector = byName[name] ?: Icons.AutoMirrored.Filled.HelpOutline

}
