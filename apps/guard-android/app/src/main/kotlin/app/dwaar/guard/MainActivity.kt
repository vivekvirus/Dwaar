package app.dwaar.guard

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.Surface
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.dwaar.guard.kiosk.KioskController
import app.dwaar.guard.ui.GuestScreen
import app.dwaar.guard.ui.HomeScreen
import app.dwaar.guard.ui.LocalIconNames
import app.dwaar.guard.ui.LocalLanguage
import app.dwaar.guard.ui.LocalTranslator
import app.dwaar.guard.ui.LoginScreen
import app.dwaar.guard.ui.NotBuiltScreen
import app.dwaar.guard.ui.ScanScreen
import app.dwaar.guard.ui.theme.GuardTheme

class MainActivity : ComponentActivity() {
    private val vm: GuardViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val container = (application as GuardApplication).container
        setContent {
            val ui by vm.ui.collectAsStateWithLifecycle()
            val guest by vm.guest.collectAsStateWithLifecycle()
            val translator = remember(ui.language) { container.catalogs.translator(ui.language) }
            CompositionLocalProvider(LocalTranslator provides translator, LocalLanguage provides ui.language, LocalIconNames provides { container.icons.iconName(it) }) {
                GuardTheme {
                    BackHandler(enabled = ui.screen != Screen.HOME && ui.screen != Screen.LOGIN) { vm.home() }
                    Surface(Modifier.fillMaxSize()) {
                        Column(Modifier.safeDrawingPadding()) {
                            when (ui.screen) {
                                Screen.LOGIN -> LoginScreen(vm, ui.language, ui.login)
                                Screen.HOME -> HomeScreen(vm, ui.banner, ui.practice, ui.practiceScenariosRun, ui.sessionSimulation, ui.contextErrorKey)
                                Screen.GUEST -> guest?.let { GuestScreen(vm, ui, it) }
                                Screen.SCAN -> ScanScreen(vm, ui.scan)
                                Screen.NOT_BUILT -> NotBuiltScreen(vm, ui.notBuiltLabelKey)
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        KioskController.enter(this) // no-op unless this app is the device owner
    }
}
