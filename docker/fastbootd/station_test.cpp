// Self-test of the station rpi-fastbootd (docker/fastbootd/otp-station.patch), run by gadget.Dockerfile
// right after the deb is built: the image build fails when any check fails.
//
// Linked from the daemon's own objects (all of them but main.cpp), so it exercises the compiled dispatcher:
// every command goes through FastbootDevice::ExecuteCommands() over a scripted transport, exactly as it would
// arrive over USB. Also checks CryptCheckNative() against a real LUKS2 header.
//
//   station_test <luks2 file> <keyslot-0 key> <keyslot-1 key>
//
// The caller creates /run/otp-keyexport/status with the content "status-ok\n" (the only directory the
// station build exchanges files with).

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "crypto_native.h"
#include "fastboot_device.h"
#include "transport.h"

namespace {

int g_failed = 0;

void Check(bool ok, const std::string& what, const std::string& got = "") {
    std::string detail = ok || got.empty() ? "" : " -- got: " + got;
    std::printf("%s %s%s\n", ok ? "PASS" : "FAIL", what.c_str(), detail.c_str());
    if (!ok) {
        ++g_failed;
    }
}

// Feeds one script element per Read (a command, or the payload of a data phase) and records every Write.
class ScriptTransport : public Transport {
  public:
    explicit ScriptTransport(std::deque<std::string> in) : in_(std::move(in)) {}
    ssize_t Read(void* data, size_t len) override {
        if (in_.empty()) {
            return 0;  // peer closed: ExecuteCommands() returns
        }
        std::string s = in_.front();
        in_.pop_front();
        size_t n = std::min(len, s.size());
        std::memcpy(data, s.data(), n);
        return static_cast<ssize_t>(n);
    }
    ssize_t Write(const void* data, size_t len) override {
        out.emplace_back(static_cast<const char*>(data), len);
        return static_cast<ssize_t>(len);
    }
    int Close() override { return 0; }
    int Reset() override { return 0; }

    std::vector<std::string> out;

  private:
    std::deque<std::string> in_;
};

// Runs a script in one session; returns everything the device wrote.
std::vector<std::string> Run(std::deque<std::string> script) {
    auto t = std::make_unique<ScriptTransport>(std::move(script));
    ScriptTransport* raw = t.get();
    std::vector<std::string> out;
    {
        FastbootDevice device(std::move(t), /*data_plane_only=*/false);
        device.ExecuteCommands();
        out = raw->out;
    }
    return out;
}

std::string Joined(const std::vector<std::string>& out) {
    std::string all;
    for (const auto& o : out) {
        all += o + "|";
    }
    return all;
}

// The final status (OKAY.../FAIL...) of a one-command session.
std::string Status(const std::string& cmd) {
    auto out = Run({cmd});
    return out.empty() ? "<none>" : out.back();
}

void ExpectRefused(const std::string& cmd, const std::string& reason) {
    std::string st = Status(cmd);
    Check(st == "FAIL" + reason, "refused: " + cmd, st);
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::fprintf(stderr, "usage: %s <luks2 file> <key0> <key1>\n", argv[0]);
        return 2;
    }
    const std::string kx = "/run/otp-keyexport", luks = argv[1], key0 = argv[2], key1 = argv[3];
    const std::string kUnknownOem = "Unknown OEM command.";

    // ---- top-level commands outside the allowlist ("shutdown" is in it and is not sent here: it powers off
    // through systemctl and then waits for the end)
    for (const char* c : {"set_active:a", "fetch:boot", "stage:00000004", "reboot-bootloader",
                          "reboot-fastboot", "snapshot-update:cancel"}) {
        std::string st = Status(c);
        Check(st.rfind("FAILUnrecognized command", 0) == 0, std::string("refused: ") + c, st);
    }
    ExpectRefused("getvar:private-key", "Unknown variable");

    // ---- OEM commands outside the allowlist, and allowed ones with other arguments
    for (const char* c : {
             "oem cryptopen mmcblk0p2 x", "oem cryptinit mmcblk0p2 L", "oem cryptsetpassword mmcblk0p2 x",
             "oem mount /dev/mmcblk0p2 /mnt", "oem umount /mnt", "oem partinit mmcblk0 gpt", "oem partapp mmcblk0 L",
             "oem led PWR 1", "oem gpioset 1=1", "oem veritysetup a b", "oem verityappend a", "oem bmap-load",
             "oem bmap-verify mmcblk0", "oem eeprom-read", "oem eeprom-update", "oem eeprom-verify",
             "oem fwcrypto sign-hash 00", "oem fwcrypto init extra", "oem fwcrypto",
             "oem upload-file /etc/passwd", "oem upload-file /dev/mmcblk0", "oem upload-file /dev/mapper/x",
             "oem upload-file /run/otp-keyexport/request", "oem upload-file /run/otp-keyexport/../../etc/passwd",
             "oem upload-file /run/otp-keyexport/status extra", "oem download-file /run/otp-keyexport/key.der",
             "oem download-file /etc/passwd", "oem ", "oem nope"}) {
        ExpectRefused(c, kUnknownOem);
    }
    for (const char* c : {"oem cryptcheck", "oem cryptcheck ../sda", "oem cryptcheck mapper/x",
                          "oem cryptcheck /dev/mmcblk0p2", "oem cryptcheck mmcblk0p2 extra"}) {
        ExpectRefused(c, "Usage: oem cryptcheck <block_device>");
    }

    // ---- allowed commands reach their handlers
    {
        // the otp-keyexport status file comes back through upload-file + upload
        auto out = Run({"oem upload-file " + kx + "/status", "upload"});
        bool fail = std::any_of(out.begin(), out.end(), [](const std::string& o) { return o.rfind("FAIL", 0) == 0; });
        size_t n = out.size();
        Check(!fail && n >= 4 && out[n - 3] == "DATA0000000a" && out[n - 2] == "status-ok\n" && out[n - 1] == "OKAY",
              "upload-file of the helper status + upload", Joined(out));
    }
    {
        auto out = Run({"download:00000007", "export\n", "oem download-file " + kx + "/request"});
        std::ifstream f(kx + "/request", std::ios::binary);
        std::stringstream ss;
        ss << f.rdbuf();
        Check(!out.empty() && out.back().rfind("OKAY", 0) == 0 && ss.str() == "export\n",
              "download + download-file of the helper request", Joined(out));
    }
    {
        std::string st = Status("oem idpdone");
        Check(st == "OKAYIDP:not initialised", "oem idpdone reaches IDP", st);
        st = Status("oem idpgetblk");
        Check(st == "FAILIDP:not initialised", "oem idpgetblk reaches IDP", st);
        // no OTP key in a container: the handler is reached and stops at the key derivation
        st = Status("oem cryptcheck mmcblk0p2");
        Check(st.rfind("FAILCannot generate LUKS key", 0) == 0, "oem cryptcheck mmcblk0p2 reaches the handler", st);
    }

    // ---- CryptCheckNative: checks a key against the keyslots, activates nothing
    {
        int slot = -1;
        std::string err;
        bool ok = CryptCheckNative(luks, key0, &slot, &err);
        Check(ok && slot == 0, "CryptCheckNative: the board key opens keyslot 0", err + " slot " + std::to_string(slot));
        slot = -1;
        ok = CryptCheckNative(luks, key1, &slot, &err);
        Check(ok && slot == 1, "CryptCheckNative: the recovery key opens keyslot 1", err + " slot " + std::to_string(slot));
        slot = -1;
        err.clear();
        ok = CryptCheckNative(luks, key0 + "x", &slot, &err);
        Check(!ok && slot == -1 && !err.empty(), "CryptCheckNative: a wrong key is refused", err);
        err.clear();
        ok = CryptCheckNative("/nonexistent", key0, &slot, &err);
        Check(!ok && !err.empty(), "CryptCheckNative: no device", err);
    }

    std::printf("%s: %d failed\n", g_failed ? "STATION TEST FAILED" : "STATION TEST OK", g_failed);
    return g_failed ? 1 : 0;
}
