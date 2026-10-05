package app.dwaar.guard.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.focusable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.automirrored.filled.Logout
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.School
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.input.key.utf16CodePoint
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import app.dwaar.guard.BuildConfig
import app.dwaar.guard.GuardViewModel
import app.dwaar.guard.core.api.DirectoryUnit
import app.dwaar.guard.core.i18n.GuardLanguage
import app.dwaar.guard.core.policy.BannerState
import app.dwaar.guard.core.policy.PolicyFreshness
import app.dwaar.guard.core.scan.KeyInput
import app.dwaar.guard.core.status.VisitDisplay
import app.dwaar.guard.core.ui.GuardPalette as P
import app.dwaar.guard.core.ui.normalizeUnitNumber
import app.dwaar.guard.core.visit.GuestStep
import app.dwaar.guard.ui.theme.c

/** Always-visible honesty strip: what is simulated or missing. English on purpose; it is for developers/supervisors. */
@Composable
fun DevStrip(sessionSimulation: Boolean, modifier: Modifier = Modifier) {
    val parts = buildList {
        add("[dev] API ${BuildConfig.API_BASE_URL}")
        if (BuildConfig.SYNC_SIMULATED) add("sync SIMULATED (no backend ack)")
        if (sessionSimulation) add("login = simulator")
        add("audio: none recorded")
    }
    Text(parts.joinToString(" | "), modifier.fillMaxWidth().background(c(P.DEV_STRIP)).padding(8.dp), color = c(P.ON_DEV_STRIP), style = MaterialTheme.typography.labelMedium)
}

@Composable
fun BackBar(onBack: () -> Unit, modifier: Modifier = Modifier) =
    GuardButton(tr("common.action.back"), Icons.AutoMirrored.Filled.ArrowBack, onBack, modifier, ButtonKind.NEUTRAL)

// ------------------------------------------------------------------------------------------------ login (UX-08)
@Composable
fun LoginScreen(vm: GuardViewModel, language: GuardLanguage, login: app.dwaar.guard.LoginUi) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(tr("common.app.name"), style = MaterialTheme.typography.headlineMedium)
        Text(tr("common.language.label"), style = MaterialTheme.typography.titleMedium)
        // Each language is written in its own script so it can be found without reading English.
        GuardLanguage.entries.forEach { l ->
            val selected = l == language
            GuardButton(
                text = (if (selected) "✓ " else "") + vm.nativeName(l),
                icon = if (selected) Icons.Filled.CheckCircle else iconFor("guard.tile.guest"),
                onClick = { vm.setLanguage(l) },
                kind = if (selected) ButtonKind.PRIMARY else ButtonKind.NEUTRAL,
            )
        }
        HorizontalDivider()
        OutlinedTextField(
            value = login.phone, onValueChange = vm::editPhone, singleLine = true, enabled = !login.otpSent && !login.busy,
            leadingIcon = { Icon(Icons.Filled.Phone, null) }, placeholder = { Text("+91 99999 00000") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone), modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
        )
        if (!login.otpSent) {
            GuardButton(tr("common.action.next"), iconFor("guard.shift.start"), vm::requestOtp, enabled = login.phone.length >= 8 && !login.busy)
        } else {
            OutlinedTextField(
                value = login.code, onValueChange = vm::editCode, singleLine = true, placeholder = { Text("• • • • • •") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword), modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
            )
            GuardButton(tr("common.action.confirm"), iconFor("guard.handover.confirm"), vm::verifyOtp, enabled = login.code.length == 6 && !login.busy)
        }
        if (login.busy) Text(tr("common.status.loading"), style = MaterialTheme.typography.bodyLarge)
        login.errorKey?.let { ErrorLine(errorText(it, login.retryAfter)) }
    }
}

@Composable
fun ErrorLine(text: String) = Row(
    Modifier.fillMaxWidth().background(c(P.NEGATIVE_CONTAINER), RoundedCornerShape(12.dp)).padding(12.dp), verticalAlignment = Alignment.CenterVertically,
) {
    Icon(iconFor("guard.nav.incident"), null, tint = c(P.ON_NEGATIVE_CONTAINER)); Spacer(Modifier.width(12.dp))
    Text(text, color = c(P.ON_NEGATIVE_CONTAINER), style = MaterialTheme.typography.bodyLarge)
}

// ------------------------------------------------------------------------------------------------ home (GATE-09)
@Composable
fun BannerBar(b: BannerState) {
    Column(Modifier.fillMaxWidth().background(c(P.SURFACE), RoundedCornerShape(12.dp)).padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        BannerLine(if (b.online) "guard.banner.online" else "guard.banner.offline", tr(if (b.online) "guard.banner.online" else "guard.banner.offline"))
        when (b.freshness) {
            PolicyFreshness.FRESH -> BannerLine("guard.banner.policy_age", tr("guard.banner.policy_age", "minutes" to (b.policyAgeMinutes ?: 0)))
            else -> BannerLine("guard.banner.policy_stale", tr("guard.banner.policy_stale"))
        }
        if (b.pendingOutbox > 0) BannerLine("guard.queue.pending", tr("guard.queue.pending", "count" to b.pendingOutbox))
        else BannerLine("guard.queue.empty", tr("guard.queue.empty"))
        if (b.autoTimeSensitiveGuestApprovalDisabled) Text("[dev] clock unverified: automatic time-sensitive guest approval disabled (EDGE-05)", style = MaterialTheme.typography.labelMedium)
    }
}

@Composable
private fun BannerLine(iconId: String, text: String) = Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.heightIn(min = 32.dp)) {
    Icon(iconFor(iconId), null, Modifier.size(24.dp)); Spacer(Modifier.width(8.dp)); Text(text, style = MaterialTheme.typography.bodyLarge)
}

@Composable
fun HomeScreen(vm: GuardViewModel, banner: BannerState, practice: Boolean, practiceRun: Int, sessionSimulation: Boolean, contextErrorKey: String?) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        BannerBar(banner)
        contextErrorKey?.let { ErrorLine(errorText(it)) }
        if (practice) Row(Modifier.fillMaxWidth().background(c(P.WARN_CONTAINER), RoundedCornerShape(12.dp)).padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(iconFor("guard.training.banner"), null, tint = c(P.ON_WARN_CONTAINER)); Spacer(Modifier.width(8.dp))
            Text(tr("guard.training.banner") + " ($practiceRun/5)", color = c(P.ON_WARN_CONTAINER), style = MaterialTheme.typography.titleMedium)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            Tile(tr("guard.tile.guest"), iconFor("guard.tile.guest"), vm::openGuest, Modifier.weight(1f))
            Tile(tr("guard.tile.delivery"), iconFor("guard.tile.delivery"), { vm.notBuilt("guard.tile.delivery") }, Modifier.weight(1f))
            Tile(tr("guard.tile.service"), iconFor("guard.tile.service"), { vm.notBuilt("guard.tile.service") }, Modifier.weight(1f))
        }
        GuardButton(tr("guard.nav.scan"), iconFor("guard.nav.scan"), vm::openScan, kind = ButtonKind.NEUTRAL)
        GuardButton(tr("guard.nav.parcels"), iconFor("guard.nav.parcels"), { vm.notBuilt("guard.nav.parcels") }, kind = ButtonKind.NEUTRAL)
        GuardButton(tr("guard.nav.inside"), iconFor("guard.nav.inside"), { vm.notBuilt("guard.nav.inside") }, kind = ButtonKind.NEUTRAL)
        GuardButton(tr("guard.nav.incident"), iconFor("guard.nav.incident"), { vm.notBuilt("guard.nav.incident") }, kind = ButtonKind.NEUTRAL)
        HorizontalDivider()
        GuardButton(
            tr("guard.training.banner"), Icons.Filled.School, vm::togglePractice,
            kind = if (practice) ButtonKind.PRIMARY else ButtonKind.NEUTRAL,
        )
        GuardButton(tr("common.action.sign_out"), Icons.AutoMirrored.Filled.Logout, vm::signOut, kind = ButtonKind.NEUTRAL)
        AudioHook("guard.tile.guest")
        DevStrip(sessionSimulation)
    }
}

@Composable
fun NotBuiltScreen(vm: GuardViewModel, labelKey: String?) {
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        BackBar(vm::home)
        Text(labelKey?.let { tr(it) }.orEmpty(), style = MaterialTheme.typography.headlineMedium)
        Text("[dev] This flow is not built yet (slice 2 implements only Guest).", style = MaterialTheme.typography.bodyLarge)
    }
}

// ------------------------------------------------------------------------------------------------ scan (UX-10 skeleton)
@Composable
fun ScanScreen(vm: GuardViewModel, scan: app.dwaar.guard.ScanUi) {
    val focus = remember { FocusRequester() }
    androidx.compose.runtime.LaunchedEffect(Unit) { focus.requestFocus() }
    Column(
        Modifier.fillMaxSize().padding(16.dp).focusRequester(focus).focusable().onPreviewKeyEvent { e ->
            if (e.type != KeyEventType.KeyDown) return@onPreviewKeyEvent false
            val at = e.nativeKeyEvent.eventTime
            when {
                e.key == Key.Enter || e.key == Key.NumPadEnter || e.key == Key.Tab -> { vm.scanKey(KeyInput.Terminator(at)); true }
                e.utf16CodePoint != 0 && !Character.isISOControl(e.utf16CodePoint) -> { vm.scanKey(KeyInput.Char(e.utf16CodePoint.toChar(), at)); true }
                else -> false
            }
        },
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        BackBar(vm::home)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(iconFor("guard.nav.scan"), null, Modifier.size(48.dp)); Spacer(Modifier.width(12.dp))
            Text(tr("guard.nav.scan"), style = MaterialTheme.typography.headlineMedium)
        }
        Surface(color = c(P.SURFACE), shape = RoundedCornerShape(16.dp), border = BorderStroke(2.dp, c(P.OUTLINE)), modifier = Modifier.fillMaxWidth().heightIn(min = 96.dp)) {
            Box(Modifier.padding(16.dp), contentAlignment = Alignment.CenterStart) {
                Text(scan.lastCode ?: "…", style = MaterialTheme.typography.titleLarge)
            }
        }
        scan.source?.let { Text("[dev] source: $it (decoded text only; passes are not validated in this slice)", style = MaterialTheme.typography.labelMedium) }
        Text("[dev] HID wedge scanner input works; camera scanning is not built.", style = MaterialTheme.typography.labelMedium)
    }
}

// ------------------------------------------------------------------------------------------------ guest flow (GATE-02)
@Composable
fun GuestScreen(vm: GuardViewModel, ui: app.dwaar.guard.UiState, state: app.dwaar.guard.core.visit.GuestFlowState) {
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (state.step == GuestStep.CHOOSE_UNIT || state.step == GuestStep.CONSENT_DECLINED) BackBar(vm::home)
        if (state.practice) Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(iconFor("guard.training.banner"), null); Spacer(Modifier.width(8.dp)); Text(tr("guard.training.banner"), style = MaterialTheme.typography.titleMedium)
        }
        when (state.step) {
            GuestStep.CHOOSE_UNIT -> {
                state.error?.let { ErrorLine(errorText(it.catalogKey, it.retryAfterSeconds)) }
                ChooseUnit(vm, ui)
            }
            GuestStep.CONFIRM_SURNAME -> state.unit?.let { ConfirmSurname(vm, it, state.surnameHint, state.hintLoading) }
            GuestStep.NOTICE_CONSENT -> Consent(vm, state)
            GuestStep.SUBMITTING -> Text(tr("common.status.loading"), style = MaterialTheme.typography.titleLarge)
            GuestStep.REQUESTED -> Requested(vm, state)
            GuestStep.CONSENT_DECLINED -> Text(tr("visitor.consent.decline"), style = MaterialTheme.typography.headlineMedium)
        }
    }
}

@Composable
private fun unitLabel(u: DirectoryUnit) = u.tower + " · " + tr("common.unit.label", "unit" to normalizeUnitNumber(u.label))

@Composable
private fun ChooseUnit(vm: GuardViewModel, ui: app.dwaar.guard.UiState) {
    val picker = ui.picker
    ui.unitsErrorKey?.let { ErrorLine(errorText(it)) }
    if (picker == null) { Text(tr("common.status.loading")); return }
    var tower by rememberSaveable { mutableStateOf<String?>(null) }
    LazyVerticalGrid(columns = GridCells.Adaptive(150.dp), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        val recents = picker.recentDestinations()
        if (recents.isNotEmpty()) {
            item(span = { GridItemSpan(maxLineSpan) }) { Text(tr("common.action.back").let { "↺" }, style = MaterialTheme.typography.titleMedium) }
            items(recents, key = { "r" + it.unitId }) { UnitButton(it, vm) }
        }
        item(span = { GridItemSpan(maxLineSpan) }) { Text(tr("guard.tile.guest"), style = MaterialTheme.typography.titleLarge) }
        // Tower first, then the units of that tower.
        items(picker.towers, key = { "t$it" }) { t ->
            GuardButton(t, iconFor("guard.handover.check_unit"), { tower = t }, kind = if (t == tower) ButtonKind.PRIMARY else ButtonKind.NEUTRAL)
        }
        tower?.let { t -> items(picker.unitsIn(t), key = { "u" + it.unitId }) { UnitButton(it, vm) } }
    }
}

@Composable
private fun UnitButton(u: DirectoryUnit, vm: GuardViewModel) =
    GuardButton(unitLabel(u), iconFor("guard.handover.check_unit"), { vm.selectUnit(u) }, kind = ButtonKind.NEUTRAL)

@Composable
private fun ConfirmSurname(vm: GuardViewModel, u: DirectoryUnit, hint: String?, loading: Boolean) {
    Text(unitLabel(u), style = MaterialTheme.typography.headlineMedium)
    // Masked surname hint only: the guard never sees the full name or any phone number (GATE-02, GATE-13).
    Surface(color = c(P.SURFACE), shape = RoundedCornerShape(16.dp), border = BorderStroke(2.dp, c(P.OUTLINE)), modifier = Modifier.fillMaxWidth()) {
        Text(if (loading) tr("common.status.loading") else hint.orEmpty(), Modifier.padding(24.dp), style = MaterialTheme.typography.headlineMedium)
    }
    GuardButton(tr("common.action.confirm"), iconFor("guard.decision.allow"), { vm.surnameMatches(true) }, kind = ButtonKind.ALLOW, enabled = !loading && hint != null)
    GuardButton(tr("common.action.back"), iconFor("guard.decision.deny"), { vm.surnameMatches(false) }, kind = ButtonKind.DENY)
}

@Composable
private fun Consent(vm: GuardViewModel, state: app.dwaar.guard.core.visit.GuestFlowState) {
    var alias by rememberSaveable { mutableStateOf("") }
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        state.unit?.let { Text(unitLabel(it), style = MaterialTheme.typography.titleLarge) }
        Text(tr("visitor.notice.title"), style = MaterialTheme.typography.headlineMedium)
        Text(tr("visitor.notice.body"), style = MaterialTheme.typography.bodyLarge)
        OutlinedTextField(
            value = alias, onValueChange = { alias = it }, singleLine = true, leadingIcon = { Icon(iconFor("guard.tile.guest"), null) },
            label = { Text(tr("guard.tile.guest")) }, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
        )
        Text(tr("visitor.consent.title"), style = MaterialTheme.typography.titleMedium)
        GuardButton(tr("visitor.consent.accept"), Icons.Filled.CheckCircle, { vm.acceptAndSubmit(alias) }, kind = ButtonKind.ALLOW, enabled = alias.isNotBlank())
        GuardButton(tr("visitor.consent.decline"), iconFor("guard.decision.deny"), vm::declineConsent, kind = ButtonKind.DENY)
        state.error?.let { ErrorLine(errorText(it.catalogKey, it.retryAfterSeconds)) }
    }
}

private val AUDIO_FOR_DISPLAY = mapOf(
    VisitDisplay.SUBMITTED to "guard.visitor.waiting_approval",
    VisitDisplay.NO_RESPONSE to "guard.visitor.no_response",
    VisitDisplay.SAVED_AWAITING_SYNC to "guard.commit.saved",
)

@Composable
private fun Requested(vm: GuardViewModel, state: app.dwaar.guard.core.visit.GuestFlowState) {
    val d = state.display ?: return
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        state.unit?.let { Text(unitLabel(it), style = MaterialTheme.typography.titleLarge) }
        val countdown = d.countdownSeconds?.let { "%02d:%02d".format(it / 60, it % 60) }
        StatusCard(d.display, extra = countdown)
        AUDIO_FOR_DISPLAY[d.display]?.let { AudioHook(it) }
        // Physical entry is a guard observation, recorded locally first (Room outbox) and synced later.
        if (d.canRecordEntry) GuardButton(tr("states.visit.entered"), iconFor("guard.handover.confirm"), vm::recordEntry, kind = ButtonKind.ALLOW)
        if (d.offerCallFallback) {
            // Masked-proxy calling (GATE-13) is not built; the control is present but disabled so nobody dials a raw number.
            GuardButton(tr("guard.visitor.call_resident"), iconFor("guard.visitor.call_resident"), {}, kind = ButtonKind.NEUTRAL, enabled = false)
            Text("[dev] masked call not built (GATE-13)", style = MaterialTheme.typography.labelMedium)
        }
        state.error?.let { ErrorLine(errorText(it.catalogKey, it.retryAfterSeconds)) }
        GuardButton(tr("common.action.done"), Icons.Filled.Refresh, vm::guestDone, kind = ButtonKind.NEUTRAL)
        GuardButton(tr("common.action.back"), Icons.Filled.Close, vm::home, kind = ButtonKind.NEUTRAL)
    }
}

