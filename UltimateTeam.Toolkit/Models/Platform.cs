using System;

namespace UltimateTeam.Toolkit.Models
{
    [Flags]
    public enum Platform
    {
        Ps3 = 1,
        Ps4 = 2,
        Xbox360 = 4,
        XboxOne = 8,
        Pc = 16,
        Switch = 32
    }
}