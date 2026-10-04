// ---------------------------------------------------------------------------
// qrcav ns-3 scenario: post-quantum V2X over IEEE 802.11p.
//
// Compiled at run time by cppyy through the ns-3 Python bindings
// (qrcav/sim/ns3_runner.py). Python supplies:
//   * RSU positions and vehicle waypoints (Manhattan-grid mobility)
//   * the exact size of every protocol message, measured from the real code
//   * empirical samples of processing time at every protocol stage
// and reads back the measured results.
//
// Nodes
//   vehicles  802.11p (5.9 GHz, 10 MHz, 6 Mb/s, ad-hoc / OCB-like)
//   RSUs      802.11p + point-to-point backhaul to the MEC
//   MEC       point-to-point to every RSU
//
// Protocol carried (sizes and delays from the Python implementation)
//   RSU  -> *   ANNOUNCE broadcast every 100 ms (service advertisement)
//   CAV <-> RSU four-flight handshake: CH, SH, CK(+Finished), FS
//               messages larger than one frame are fragmented into 1400-byte
//               chunks; a lost chunk triggers a whole-flight retransmission
//   CAV  -> RSU beacons at beacon_hz, AEAD records or ML-DSA-signed
//   CAV  -> RSU -> MEC critical events; MEC -> all RSUs -> broadcast ALERT
//   MEC         consensus commit time drawn from the measured distribution
// ---------------------------------------------------------------------------

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"

#include <cmath>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace qrcav
{
using namespace ns3;

enum MsgType : uint8_t
{
    ANNOUNCE = 1, CH = 2, SH = 3, CK = 4, FS = 5, BEACON = 6,
    EVENT = 7, ALERT = 8, EVENT_BH = 9, ALERT_BH = 10, NACK = 11
};

static const uint32_t HDR = 24;      // type, chunk, nchunks, src, msgid, t0
static const uint32_t CHUNK = 1400;  // application payload per frame
static const uint16_t PORT = 9000;
static const uint32_t MEC_ID = 2000000;
static const uint32_t RSU_BASE = 1000000;

// ---- inputs ----------------------------------------------------------------
static std::map<std::string, double> P;                       // scalar params
static std::map<std::string, std::vector<double>> S;          // timing samples (ms)
static std::vector<std::vector<std::vector<double>>> WP;      // vehicle waypoints [v][k] = {t,x,y}
static std::vector<std::vector<double>> RSUPOS;               // [r] = {x,y}

// ---- outputs ---------------------------------------------------------------
static std::map<std::string, std::vector<double>> R;
static std::map<std::string, double> C;

static std::mt19937_64 rng;

double par(const std::string& k, double d)
{
    auto it = P.find(k);
    return it == P.end() ? d : it->second;
}

double sample(const std::string& k)
{
    auto it = S.find(k);
    if (it == S.end() || it->second.empty())
        return 0.0;
    std::uniform_int_distribution<size_t> u(0, it->second.size() - 1);
    return it->second[u(rng)];
}

uint32_t sz(const std::string& k)
{
    return static_cast<uint32_t>(par("size_" + k, 100));
}

void count(const std::string& k, double v = 1.0) { C[k] += v; }
void rec(const std::string& k, double v) { R[k].push_back(v); }

// ---- wire format -----------------------------------------------------------
struct Hdr
{
    uint8_t type;
    uint8_t pad;
    uint16_t chunk;
    uint16_t nchunks;
    uint16_t res;
    uint32_t src;
    uint32_t msgid;
    double t0;
};
static_assert(sizeof(Hdr) == HDR, "header size");

struct Msg
{
    uint8_t type;
    uint32_t src;
    uint32_t msgid;
    double t0;
    uint16_t aux;    // NACK: bitmap of chunks held; BEACON: index of the target RSU
};

class Endpoint;
static std::vector<Endpoint*> g_eps;

// A node's single UDP socket plus fragmentation and reassembly.
class Endpoint
{
  public:
    Ptr<Socket> sock;      // best effort (AC_BE): handshake flights
    Ptr<Socket> sockHi;    // voice (AC_VO): announces, beacons, events, alerts
    uint32_t id = 0;
    double cpuBusyUntil = 0.0;
    std::map<std::pair<uint32_t, uint32_t>, std::pair<uint16_t, std::set<uint16_t>>> reasm;

    virtual ~Endpoint() = default;
    virtual void OnMsg(const Msg& m, Address from) = 0;

    void Setup(Ptr<Node> node)
    {
        sock = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
        sock->Bind(InetSocketAddress(Ipv4Address::GetAny(), PORT));
        sock->SetAllowBroadcast(true);
        sock->SetRecvCallback(MakeCallback(&Endpoint::Recv, this));
        sockHi = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
        sockHi->Bind();
        sockHi->SetAllowBroadcast(true);
        if (par("edca", 1) > 0)
        {
            sock->SetPriority(0);    // user priority 0 -> AC_BE
            sockHi->SetPriority(6);  // user priority 6 -> AC_VO
        }
    }

    static bool Urgent(uint8_t type)
    {
        return type == ANNOUNCE || type == BEACON || type == EVENT || type == ALERT;
    }

    // Queue work on this node's CPU: returns the completion time (seconds).
    double Cpu(double ms)
    {
        double now = Simulator::Now().GetSeconds();
        double start = std::max(now, cpuBusyUntil);
        cpuBusyUntil = start + ms / 1000.0;
        return cpuBusyUntil;
    }

    // Send a message, fragmented into CHUNK-byte frames. `have` is a bitmap of
    // chunks the receiver already holds (selective retransmission after a NACK).
    void Send(Address to, uint8_t type, uint32_t bytes, uint32_t msgid, double t0, uint16_t have = 0,
              uint16_t aux = 0)
    {
        uint16_t n = static_cast<uint16_t>(std::max<uint32_t>(1, (bytes + CHUNK - 1) / CHUNK));
        for (uint16_t i = 0; i < n; ++i)
        {
            if (i < 16 && (have >> i & 1))
                continue;
            uint32_t body = (i + 1 < n) ? CHUNK : bytes - CHUNK * (n - 1);
            if (bytes == 0)
                body = 0;
            std::vector<uint8_t> buf(HDR + body, 0);
            Hdr h{type, 0, i, n, aux, id, msgid, t0};
            std::memcpy(buf.data(), &h, HDR);
            Ptr<Packet> p = Create<Packet>(buf.data(), buf.size());
            (Urgent(type) ? sockHi : sock)->SendTo(p, 0, to);
            count("tx_bytes", buf.size());
            count("tx_frames");
            count(std::string("tx_frames_t") + std::to_string(type));
        }
    }

    void Recv(Ptr<Socket> s)
    {
        Address from;
        Ptr<Packet> p;
        while ((p = s->RecvFrom(from)))
        {
            if (p->GetSize() < HDR)
                continue;
            Hdr h;
            p->CopyData(reinterpret_cast<uint8_t*>(&h), HDR);
            if (h.src == id)
                continue;
            if (h.nchunks <= 1)
            {
                OnMsg(Msg{h.type, h.src, h.msgid, h.t0, h.res}, from);
                continue;
            }
            auto key = std::make_pair(h.src, h.msgid * 16u + h.type);
            auto& e = reasm[key];
            e.first = h.nchunks;
            e.second.insert(h.chunk);
            if (e.second.size() == h.nchunks)
            {
                reasm.erase(key);
                OnMsg(Msg{h.type, h.src, h.msgid, h.t0, 0}, from);
            }
            if (reasm.size() > 4096)
                reasm.clear();
        }
    }

    // Bitmap of chunks already received for (src, msgid, type).
    uint16_t Have(uint32_t src, uint32_t msgid, uint8_t type)
    {
        auto it = reasm.find(std::make_pair(src, msgid * 16u + type));
        uint16_t m = 0;
        if (it != reasm.end())
            for (uint16_t c : it->second.second)
                if (c < 16)
                    m |= static_cast<uint16_t>(1u << c);
        return m;
    }
};

static std::map<uint32_t, Address> g_addr;        // node id -> wifi address
static std::map<uint32_t, Address> g_bhaddr;      // RSU id -> backhaul address (as seen by MEC)
static Address g_mecaddr_for[4096];               // per RSU: MEC address on that link

// ---------------------------------------------------------------------------
class Mec : public Endpoint
{
  public:
    std::vector<uint32_t> rsus;
    void OnMsg(const Msg& m, Address) override
    {
        if (m.type != EVENT_BH)
            return;
        double done = Cpu(par("mec_route_ms", 0.05));
        Simulator::Schedule(Seconds(done - Simulator::Now().GetSeconds()), &Mec::Actuate, this, m);
        // ledger: commit latency drawn from the measured AGS-PBFT distribution
        double commit = sample(par("pbft", 0) > 0 ? "commit_pbft" : "commit_ags") / 1000.0;
        rec("commit_latency_ms", (Simulator::Now().GetSeconds() + commit - m.t0) * 1000.0);
        rec("mec_latency_ms", (Simulator::Now().GetSeconds() - m.t0) * 1000.0);
    }
    void Actuate(Msg m)
    {
        for (uint32_t r : rsus)
            Send(g_bhaddr[r], ALERT_BH, sz("alert"), m.msgid, m.t0);
    }
};

// ---------------------------------------------------------------------------
class Rsu : public Endpoint
{
  public:
    uint32_t idx = 0;
    // per vehicle: handshake msgid and phase
    //   1 processing CH, 2 SH sent, 3 processing CK, 4 FS sent (session up)
    std::map<uint32_t, uint32_t> hsMsg;
    std::map<uint32_t, int> phase;

    void Start()
    {
        Announce();
    }
    void Announce()
    {
        Send(InetSocketAddress(Ipv4Address("10.1.255.255"), PORT), ANNOUNCE, sz("announce"), 0, 0);
        Simulator::Schedule(MilliSeconds(100), &Rsu::Announce, this);
    }
    bool Up(uint32_t v) { return phase.count(v) && phase[v] == 4; }
    void OnMsg(const Msg& m, Address from) override
    {
        double now = Simulator::Now().GetSeconds();
        switch (m.type)
        {
        case CH: {
            if (hsMsg.count(m.src) && hsMsg[m.src] == m.msgid)
            {
                if (phase[m.src] == 2)          // our SH was lost: resend it
                    SendTo(m.src, SH, sz("server_hello"), m.msgid, 2);
                return;                          // otherwise a duplicate; ignore
            }
            hsMsg[m.src] = m.msgid;
            phase[m.src] = 1;
            double done = Cpu(sample("server_ch"));
            Simulator::Schedule(Seconds(done - now), &Rsu::SendTo, this, m.src, (uint8_t)SH,
                                sz("server_hello"), m.msgid, 2);
            break;
        }
        case NACK: {
            // selective retransmission: resend only the ServerHello chunks the vehicle lacks
            if (hsMsg.count(m.src) && hsMsg[m.src] == m.msgid && phase[m.src] == 2)
            {
                count("sh_selective_retx");
                Send(g_addr[m.src], SH, sz("server_hello"), m.msgid, now, m.aux);
            }
            break;
        }
        case CK: {
            if (!hsMsg.count(m.src) || hsMsg[m.src] != m.msgid)
                return;
            if (phase[m.src] == 4)
            {   // our FS was lost: resend it
                SendTo(m.src, FS, sz("server_finished"), m.msgid, 4);
                return;
            }
            if (phase[m.src] != 2)
                return;
            phase[m.src] = 3;
            double done = Cpu(sample("server_ck"));
            Simulator::Schedule(Seconds(done - now), &Rsu::SendTo, this, m.src, (uint8_t)FS,
                                sz("server_finished"), m.msgid, 4);
            break;
        }
        case BEACON: {
            if (m.aux != idx)
                return;                          // meant for another RSU's session
            if (!Up(m.src))
            {
                count("beacon_no_session_at_rsu");
                return;
            }
            double done = Cpu(sample(par("signed", 0) > 0 ? "beacon_verify" : "beacon_open"));
            if (m.t0 > 0)
            {
                rec("beacon_latency_ms", (done - m.t0) * 1000.0);
                count("beacon_rx");
            }
            break;
        }
        case EVENT: {
            if (!Up(m.src))
                return;
            double done = Cpu(sample("beacon_open"));
            Simulator::Schedule(Seconds(done - now), &Rsu::Forward, this, m);
            break;
        }
        case ALERT_BH: {
            double done = Cpu(sample("beacon_seal"));
            Simulator::Schedule(Seconds(done - now), &Rsu::Broadcast, this, m);
            break;
        }
        default:
            break;
        }
    }
    void SendTo(uint32_t veh, uint8_t type, uint32_t bytes, uint32_t msgid, int newPhase)
    {
        if (hsMsg[veh] != msgid)
            return;                              // superseded by a newer handshake
        phase[veh] = newPhase;
        Send(g_addr[veh], type, bytes, msgid, Simulator::Now().GetSeconds());
    }
    void Forward(Msg m)
    {
        Send(g_mecaddr_for[idx], EVENT_BH, sz("event"), m.msgid, m.t0);
    }
    void Broadcast(Msg m)
    {
        Send(InetSocketAddress(Ipv4Address("10.1.255.255"), PORT), ALERT, sz("alert"), m.msgid, m.t0);
    }
};

// ---------------------------------------------------------------------------
class Vehicle : public Endpoint
{
  public:
    enum St { IDLE, WAIT_SH, WAIT_FS, UP };
    St st = IDLE;
    int rsu = -1;
    uint32_t hsMsg = 0;
    uint32_t nextMsg = 1;
    uint32_t nextEvent = 1;
    int retries = 0;
    double hsStart = 0;
    double upSince = -1;
    std::map<int, double> heard;    // rsu idx -> last announce time
    std::map<int, std::deque<double>> recent;   // rsu idx -> announce times in the last second
    EventId timer;
    std::set<uint32_t> alertsSeen;
    int failCount = 0;
    double notBefore = 0.0;     // exponential backoff after failed handshakes

    void Backoff()
    {
        if (par("backoff", 1) <= 0)
            return;
        failCount++;
        std::uniform_real_distribution<double> u(0.5, 1.0);
        notBefore = Simulator::Now().GetSeconds() + u(rng) * std::pow(2.0, std::min(failCount, 4));
    }

    void Start()
    {
        double hz = par("beacon_hz", 10);
        std::uniform_real_distribution<double> u(0, 1.0 / hz);
        Simulator::Schedule(Seconds(u(rng)), &Vehicle::Beacon, this);
        ScheduleEvent();
        Simulator::Schedule(Seconds(0.5), &Vehicle::LinkCheck, this);
    }

    void ScheduleEvent()
    {
        double rate = par("event_rate", 0.0);   // events per second per vehicle
        if (rate <= 0)
            return;
        std::exponential_distribution<double> e(rate);
        Simulator::Schedule(Seconds(e(rng)), &Vehicle::Event, this);
    }

    void Event()
    {
        count("events_created");
        if (st == UP && Simulator::Now().GetSeconds() > par("warmup", 5))
        {
            uint32_t mid = id * 100000u + (nextEvent++ % 100000u);   // globally unique event id
            double done = Cpu(sample("beacon_seal"));
            Simulator::Schedule(Seconds(done - Simulator::Now().GetSeconds()), &Vehicle::SendEvent, this,
                                mid, Simulator::Now().GetSeconds());
        }
        else if (Simulator::Now().GetSeconds() > par("warmup", 5))
            count("events_no_session");
        ScheduleEvent();
    }
    void SendEvent(uint32_t mid, double t0)
    {
        count("events_sent");
        Send(g_addr[RSU_BASE + rsu], EVENT, sz("event"), mid, t0);
    }

    void Beacon()
    {
        double now = Simulator::Now().GetSeconds();
        bool measure = now > par("warmup", 5);
        if (measure)
            count("beacon_slots");
        if (st == UP)
        {
            bool sgn = par("signed", 0) > 0;
            double done = Cpu(sample(sgn ? "beacon_sign" : "beacon_seal"));
            Simulator::Schedule(Seconds(done - now), &Vehicle::SendBeacon, this, now, measure);
        }
        else if (measure)
            count("beacon_slots_no_session");
        Simulator::Schedule(Seconds(1.0 / par("beacon_hz", 10)), &Vehicle::Beacon, this);
    }
    void SendBeacon(double t0, bool measure)
    {
        if (st != UP)
            return;
        if (measure)
            count("beacon_tx");
        // Periodic safety messages are link-layer broadcasts (no ACK, no MAC retries),
        // as BSMs / CAMs are. Only the associated RSU holds the session key to open it.
        Send(InetSocketAddress(Ipv4Address("10.1.255.255"), PORT), BEACON,
             sz(par("signed", 0) > 0 ? "beacon_signed" : "beacon_aead"), nextMsg++, measure ? t0 : -1e9,
             0, static_cast<uint16_t>(rsu));
    }

    // Number of announcements heard from RSU r in the last second (link quality).
    size_t Quality(int r)
    {
        double now = Simulator::Now().GetSeconds();
        auto it = recent.find(r);
        if (it == recent.end())
            return 0;
        while (!it->second.empty() && now - it->second.front() > 1.0)
            it->second.pop_front();
        return it->second.size();
    }

    void LinkCheck()
    {
        double now = Simulator::Now().GetSeconds();
        // Handover with hysteresis: move to a clearly better RSU (a new handshake)
        if (st == UP && rsu >= 0)
        {
            size_t cur = Quality(rsu);
            int best = rsu;
            for (auto& kv : recent)
                if (Quality(kv.first) > Quality(best))
                    best = kv.first;
            if (best != rsu && Quality(best) >= cur + par("handover_margin", 4) &&
                Quality(best) >= par("assoc_min_announces", 6))
            {
                count("handovers");
                rec("session_s", now - upSince);
                StartHandshake(best);
            }
        }
        if (rsu >= 0 && (st == UP || st == WAIT_SH || st == WAIT_FS))
        {
            auto it = heard.find(rsu);
            if (it == heard.end() || now - it->second > par("link_timeout", 1.0))
            {
                if (st == UP)
                {
                    count("links_lost");
                    rec("session_s", now - upSince);
                }
                else
                    count("handshakes_aborted_out_of_range");
                timer.Cancel();
                st = IDLE;
                rsu = -1;
            }
        }
        Simulator::Schedule(Seconds(0.1), &Vehicle::LinkCheck, this);
    }

    void StartHandshake(int r)
    {
        rsu = r;
        hsMsg = nextMsg++;
        retries = 0;
        hsStart = Simulator::Now().GetSeconds();
        if (hsStart > par("warmup", 5))
            count("handshake_attempts");
        double done = Cpu(sample("client_ch"));
        st = WAIT_SH;
        Simulator::Schedule(Seconds(done - hsStart), &Vehicle::SendFlight, this, (uint8_t)CH);
    }

    void SendFlight(uint8_t type)
    {
        if ((type == CH && st != WAIT_SH) || (type == CK && st != WAIT_FS))
            return;
        uint32_t bytes = sz(type == CH ? "client_hello" : "client_key");
        Send(g_addr[RSU_BASE + rsu], type, bytes, hsMsg, hsStart);
        timer.Cancel();
        timer = Simulator::Schedule(MilliSeconds(par("hs_timeout_ms", 400)), &Vehicle::Timeout, this, type);
    }

    void Timeout(uint8_t type)
    {
        if (++retries > par("hs_retries", 3))
        {
            if (hsStart > par("warmup", 5))
                count("handshakes_failed");
            st = IDLE;
            rsu = -1;
            Backoff();
            return;
        }
        count("handshake_retx");
        if (type == CH && st == WAIT_SH)
        {
            uint16_t have = Have(RSU_BASE + rsu, hsMsg, SH);
            if (have)
            {   // part of the ServerHello arrived: ask only for the rest
                Send(g_addr[RSU_BASE + rsu], NACK, 8, hsMsg, hsStart, 0, have);
                timer = Simulator::Schedule(MilliSeconds(par("hs_timeout_ms", 200)), &Vehicle::Timeout, this, type);
                return;
            }
        }
        SendFlight(type);
    }

    void OnMsg(const Msg& m, Address) override
    {
        double now = Simulator::Now().GetSeconds();
        if (m.type == ANNOUNCE)
        {
            int r = static_cast<int>(m.src - RSU_BASE);
            heard[r] = now;
            auto& q = recent[r];
            q.push_back(now);
            while (!q.empty() && now - q.front() > 1.0)
                q.pop_front();
            // Link-quality gate: start the (multi-frame) handshake only with an RSU
            // whose announcements we have been receiving reliably over the last second.
            if (st == IDLE && now >= notBefore && q.size() >= par("assoc_min_announces", 6))
            {
                int best = r;
                for (auto& kv : recent)
                    if (kv.second.size() > recent[best].size())
                        best = kv.first;
                StartHandshake(best);
            }
            return;
        }
        if (m.type == ALERT)
        {
            if (alertsSeen.count(m.msgid))
                return;                          // same alert from another RSU
            alertsSeen.insert(m.msgid);
            count("alert_rx");
            if (m.msgid / 100000u == id)
            {
                count("alert_rx_origin");
                rec("alert_latency_origin_ms", (now - m.t0) * 1000.0);
            }
            else
                rec("alert_latency_others_ms", (now - m.t0) * 1000.0);
            return;
        }
        if (rsu < 0 || m.src != RSU_BASE + static_cast<uint32_t>(rsu) || m.msgid != hsMsg)
            return;
        if (m.type == SH && st == WAIT_SH)
        {
            timer.Cancel();
            retries = 0;
            st = WAIT_FS;
            double done = Cpu(sample("client_sh"));
            Simulator::Schedule(Seconds(done - now), &Vehicle::SendFlight, this, (uint8_t)CK);
        }
        else if (m.type == FS && st == WAIT_FS)
        {
            timer.Cancel();
            double done = Cpu(sample("client_fs"));
            st = UP;
            upSince = done;
            failCount = 0;
            if (hsStart > par("warmup", 5))
                count("handshakes_ok");
            if (hsStart > par("warmup", 5))     // steady state: initial association storm excluded
                rec("handshake_ms", (done - hsStart) * 1000.0);
        }
    }
};

// ---- airtime accounting ------------------------------------------------------
static double g_txAir = 0.0;
void PhyState(Time start, Time duration, WifiPhyState state)
{
    if (state == WifiPhyState::TX && start.GetSeconds() > par("warmup", 5))
        g_txAir += duration.GetSeconds();
}
void MacTxFail(Mac48Address) { count("mac_tx_failed"); }
void PhyTxBegin(Ptr<const Packet> p, double) { count("phy_tx_frames"); count("phy_tx_bytes", p->GetSize()); }

// ---- API used from Python ----------------------------------------------------------
void reset()
{
    P.clear(); S.clear(); WP.clear(); RSUPOS.clear(); R.clear(); C.clear();
    g_addr.clear(); g_bhaddr.clear(); g_eps.clear(); g_txAir = 0.0;
}
void set_param(const std::string& k, double v) { P[k] = v; }
void set_samples(const std::string& k, const std::vector<double>& v) { S[k] = v; }
void add_rsu(double x, double y) { RSUPOS.push_back({x, y}); }
void add_waypoint(int v, double t, double x, double y)
{
    if (static_cast<int>(WP.size()) <= v)
        WP.resize(v + 1);
    WP[v].push_back({t, x, y});
}
std::vector<double> get(const std::string& k) { return R[k]; }
std::vector<std::string> counter_names()
{
    std::vector<std::string> out;
    for (auto& kv : C)
        out.push_back(kv.first);
    return out;
}
double counter(const std::string& k) { return C[k]; }

void run()
{
    rng.seed(static_cast<uint64_t>(par("seed", 1)));
    RngSeedManager::SetSeed(1);
    RngSeedManager::SetRun(static_cast<uint64_t>(par("seed", 1)));
    double T = par("sim_time", 60);
    uint32_t nV = WP.size(), nR = RSUPOS.size();

    // ns-3's ARP cache holds only 3 packets per unresolved address by default, which
    // silently drops most fragments of a multi-frame first flight. Real stacks queue more.
    Config::SetDefault("ns3::ArpCache::PendingQueueSize", UintegerValue(128));
    Config::SetDefault("ns3::ArpCache::AliveTimeout", TimeValue(Seconds(600)));

    NodeContainer veh, rsu, mec;
    veh.Create(nV);
    rsu.Create(nR);
    mec.Create(1);
    NodeContainer radio(veh, rsu);

    // ---- 802.11p PHY / MAC
    YansWifiChannelHelper chan;
    chan.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    chan.AddPropagationLoss("ns3::LogDistancePropagationLossModel",
                            "Exponent", DoubleValue(par("pathloss_exp", 2.2)),
                            "ReferenceLoss", DoubleValue(47.86));      // free-space at 1 m, 5.9 GHz
    if (par("nakagami", 1) > 0)   // fast fading, VANET parameters of Torrent-Moreno et al. (2004)
        chan.AddPropagationLoss("ns3::NakagamiPropagationLossModel",
                                "Distance1", DoubleValue(50), "Distance2", DoubleValue(150),
                                "m0", DoubleValue(3.0), "m1", DoubleValue(1.5), "m2", DoubleValue(1.0));
    YansWifiPhyHelper phy;
    phy.SetChannel(chan.Create());
    phy.Set("ChannelSettings", StringValue("{172, 10, BAND_5GHZ, 0}"));
    // ns-3 defaults to -82 dBm preamble detection / CCA, the 20 MHz Wi-Fi value.
    // IEEE 802.11p in a 10 MHz channel specifies -85 dBm (3 dB lower noise bandwidth).
    phy.SetPreambleDetectionModel("ns3::ThresholdPreambleDetectionModel",
                                  "MinimumRssi", DoubleValue(par("min_rssi_dbm", -85.0)),
                                  "Threshold", DoubleValue(4.0));
    phy.Set("CcaSensitivity", DoubleValue(par("min_rssi_dbm", -85.0)));
    phy.Set("TxPowerStart", DoubleValue(par("tx_dbm", 13.0)));          // 20 mW (base paper Table 4)
    phy.Set("TxPowerEnd", DoubleValue(par("tx_dbm", 13.0)));
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211p);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode", StringValue("OfdmRate6MbpsBW10MHz"),
                                 "ControlMode", StringValue("OfdmRate6MbpsBW10MHz"),
                                 "NonUnicastMode", StringValue("OfdmRate6MbpsBW10MHz"));
    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac", "QosSupported", BooleanValue(par("edca", 1) > 0));
    NetDeviceContainer wdev = wifi.Install(phy, mac, radio);

    // ---- mobility
    MobilityHelper mv;
    mv.SetMobilityModel("ns3::WaypointMobilityModel");
    mv.Install(veh);
    for (uint32_t i = 0; i < nV; ++i)
    {
        auto wpm = DynamicCast<WaypointMobilityModel>(veh.Get(i)->GetObject<MobilityModel>());
        for (auto& w : WP[i])
            wpm->AddWaypoint(Waypoint(Seconds(w[0]), Vector(w[1], w[2], 1.5)));
    }
    MobilityHelper ms;
    Ptr<ListPositionAllocator> pos = CreateObject<ListPositionAllocator>();
    for (auto& r : RSUPOS)
        pos->Add(Vector(r[0], r[1], 6.0));
    ms.SetPositionAllocator(pos);
    ms.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    ms.Install(rsu);
    Ptr<ListPositionAllocator> mp = CreateObject<ListPositionAllocator>();
    mp->Add(Vector(0, 0, 0));
    ms.SetPositionAllocator(mp);
    ms.Install(mec);

    // ---- IP
    InternetStackHelper inet;
    inet.Install(radio);
    inet.Install(mec);
    Ipv4AddressHelper ip;
    ip.SetBase("10.1.0.0", "255.255.0.0");
    Ipv4InterfaceContainer wif = ip.Assign(wdev);

    // ---- backhaul RSU <-> MEC
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("1Gbps"));
    p2p.SetChannelAttribute("Delay", StringValue(std::to_string(par("backhaul_ms", 2.0)) + "ms"));

    std::vector<std::unique_ptr<Vehicle>> V;
    std::vector<std::unique_ptr<Rsu>> RS;
    auto M = std::make_unique<Mec>();
    M->id = MEC_ID;
    M->Setup(mec.Get(0));

    for (uint32_t i = 0; i < nV; ++i)
    {
        g_addr[i] = InetSocketAddress(wif.GetAddress(i), PORT);
        auto v = std::make_unique<Vehicle>();
        v->id = i;
        v->Setup(veh.Get(i));
        V.push_back(std::move(v));
    }
    for (uint32_t r = 0; r < nR; ++r)
    {
        uint32_t rid = RSU_BASE + r;
        g_addr[rid] = InetSocketAddress(wif.GetAddress(nV + r), PORT);
        NetDeviceContainer d = p2p.Install(rsu.Get(r), mec.Get(0));
        std::string base = "10." + std::to_string(2 + r / 256) + "." + std::to_string(r % 256) + ".0";
        ip.SetBase(base.c_str(), "255.255.255.252");
        Ipv4InterfaceContainer bi = ip.Assign(d);
        g_bhaddr[rid] = InetSocketAddress(bi.GetAddress(0), PORT);
        g_mecaddr_for[r] = InetSocketAddress(bi.GetAddress(1), PORT);
        auto x = std::make_unique<Rsu>();
        x->id = rid;
        x->idx = r;
        x->Setup(rsu.Get(r));
        M->rsus.push_back(rid);
        RS.push_back(std::move(x));
    }

    // 802.11p safety messaging (WSMP / OCB) addresses frames by MAC and has no ARP.
    // Pre-populate neighbour caches so no ARP exchange (and its 1 s retry timer) is simulated.
    NeighborCacheHelper ncache;
    ncache.PopulateNeighborCache();

    Config::ConnectWithoutContext("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/State/State",
                                  MakeCallback(&PhyState));
    Config::ConnectWithoutContext("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/RemoteStationManager/MacTxFinalDataFailed",
                                  MakeCallback(&MacTxFail));
    Config::ConnectWithoutContext("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyTxBegin",
                                  MakeCallback(&PhyTxBegin));

    for (auto& r : RS)
    {
        std::uniform_real_distribution<double> u(0, 0.1);
        Simulator::Schedule(Seconds(u(rng)), &Rsu::Start, r.get());
    }
    for (auto& v : V)
        Simulator::Schedule(Seconds(0.01), &Vehicle::Start, v.get());

    Simulator::Stop(Seconds(T));
    Simulator::Run();

    // sessions still up at the end
    for (auto& v : V)
        if (v->st == Vehicle::UP)
            rec("session_s", T - v->upSince);
    C["airtime_tx_s"] = g_txAir;
    C["measured_s"] = T - par("warmup", 5);
    Simulator::Destroy();
}

} // namespace qrcav
