namespace Interest_is_Interesting;

static class SavingsAccount
{
    public static void Main(string[] args)
    {
        SavingsAccount.InterestRate(balance: 200.75m);
        // 0.5f
        SavingsAccount.Interest(balance: 200.75m);
        // 1.00375m
        SavingsAccount.AnnualBalanceUpdate(balance: 200.75m);
        // 201.75375m
        SavingsAccount.YearsBeforeDesiredBalance(balance: 100.0m, targetBalance: 125.80m);
        // 47
    }
    public static float InterestRate(decimal balance)
    {
        switch (balance)
        {
            case >= 5000:
                return 2.475f;
            case >= 1000:
                return 1.621f;
            case >= 0:
                return 0.5f;
            default:
                return 3.213f;
        }
    }

    //wrong casting type leads to invalid precision
    //public static decimal Interest(decimal balance) => ((decimal)((float)SavingsAccount.InterestRate(balance) * (float)balance)) / 100;
    public static decimal Interest(decimal balance) => ((decimal)SavingsAccount.InterestRate(balance) * balance) / 100;

    public static decimal AnnualBalanceUpdate(decimal balance) => (decimal)balance + SavingsAccount.Interest(balance);

    public static int YearsBeforeDesiredBalance(decimal balance, decimal targetBalance)
    {
        int years = 0;
        while (balance < targetBalance)
        {
            decimal rateDecimal = (decimal)SavingsAccount.InterestRate(balance) / 100;
            balance += balance * rateDecimal;
            years++;
        }
        return years;
    }
}
