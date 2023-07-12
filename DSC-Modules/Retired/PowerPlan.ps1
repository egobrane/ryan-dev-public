Configuration PowerPlan {

    Import-DscResource -ModuleName DSCR_PowerPlan

    Node 'localhost' {

        cPowerPlan Balanced
        {
            Ensure = "Present"
            GUID = "SCHEME_BALANCED"
            Name = "Balanced"
            Active = $true
        }

        cPowerPlanSetting MonitorTimeout
        {
            PlanGuid = "SCHEME_BALANCED"
            SettingGuid = "VIDEOIDLE"
            Value = 0
            AcDc = "AC"
        }
    }
}