/*
 * demo.js — screenshot helper (run_selftest.py --screenshot ... --state demo): puts the page into a typical
 * mid-provisioning state using the runner's fake API records. Never loaded by the real page.
 */
(async function () {
    const OTP = window.OTP;
    await OTP.app.ready;
    const app = OTP.app;
    const flow = app.flow;
    const m = app.srv.modules.find((x) => x.stage === 'eeprom') || app.srv.modules[0];
    if (!m) return;
    flow.module = m;
    flow.serial = m.serial;
    flow.hooks.onModule(m);
    flow.probeInfo = { kind: 'rpiboot', rom: false };
    flow.hooks.onDevice({ fake: true }, 'rpiboot');
    app.setStep(1, 'done', 'EEPROM_UPDATE = success · metadata received (serial, MAC, DUID)', { verdict: { ok: true, notes: ['EEPROM_UPDATE = success', 'USER_SERIAL_NUM matches the board serial'] } });
    if (window.__DEMO === 'fastboot') {
        app.setStep(2, 'done', 'boot.img delivered; the board is booting the gadget', { verdict: { ok: true, notes: ['boot.img served (27632640 bytes)'] } });
        app.setStep(3, 'waiting', 'waiting for the fastboot gadget: click "Connect fastboot gadget" and pick it in Chrome\'s list (it appears once Linux has booted, ~20 s)');
        flow.running = true;
        flow.hooks.onBusy(true);
        flow.hooks.onNeed('fastboot', {});
    } else {
        app.setStep(2, 'running', 'Fastboot gadget · unsigned · bootfiles.bin, boot.img, config.txt');
        flow.hooks.onProgress(2, { label: 'boot.img', sent: 17825792, total: 27632640 });
        app.setStep(3, 'idle', '');
    }
    const L = app.log;
    L('info', `=== Provisioning ${m.serial}: stages 1, 2, 3 ===`);
    L('info', 'Found BCM2712 (Pi 5 / CM5 / Pi 500) serial a7eb274c iSerialNumber=3');
    L('info', 'Sending bootcode5.bin (104314 bytes) from server stage 1 (unsigned)/bootcode5.bin');
    L('ok', 'Second stage accepted (status 0); the device will re-enumerate');
    L('meta', 'USER_SERIAL_NUM = a7eb274c');
    L('meta', 'MAC_ADDR = 2c:cf:67:70:76:f3');
    L('meta', 'EEPROM_UPDATE = success');
    L('ok', 'Stage 1 (EEPROM & OTP) done: EEPROM_UPDATE = success');
    L('info', 'Loading: bootfiles.bin:2712/bootcode5.bin (104314 bytes)');
    L('info', 'Loading: server stage 2 (unsigned)/boot.img (27632640 bytes)');
    document.body.dataset.demo = 'ready';
})();
