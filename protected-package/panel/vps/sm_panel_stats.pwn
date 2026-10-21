// Server Security Monitor v3.0
// Created by FacuSecX
// https://github.com/FacuSecX/
#define FILTERSCRIPT
#include <a_samp>

new panelStatsTimer;
new panelStatsStarted;
forward PanelWriteStats();

public OnFilterScriptInit()
{
    panelStatsStarted = gettime();
    PanelWriteStats();
    panelStatsTimer = SetTimer("PanelWriteStats", 2000, true);
    return 1;
}

public OnFilterScriptExit()
{
    KillTimer(panelStatsTimer);
    return 1;
}

public PanelWriteStats()
{
    new players, maximum = GetMaxPlayers(), data[144];
    for (new id; id < maximum; id++)
    {
        if (IsPlayerConnected(id)) players++;
    }
    format(data, sizeof(data), "{\"v\":1,\"players\":%d,\"maximum\":%d,\"at\":%d,\"started\":%d}", players, maximum, gettime(), panelStatsStarted);
    new File:first = fopen("server_monitor_players_0.dat", io_write);
    if (first) { fwrite(first, data); fclose(first); }
    new File:second = fopen("server_monitor_players_1.dat", io_write);
    if (second) { fwrite(second, data); fclose(second); }
    return 1;
}
