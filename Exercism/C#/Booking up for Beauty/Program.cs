namespace Booking_up_for_Beauty;

class Appointment
{
    static void Main(string[] args)
    {
        Appointment.Schedule("7/25/2019 13:45:00");
        // => new DateTime(2019, 7, 25, 13, 45, 0)
        Appointment.HasPassed(new DateTime(1999, 12, 31, 9, 0, 0));
        // => true
        Appointment.IsAfternoonAppointment(new DateTime(2019, 03, 29, 15, 0, 0));
        // => true
        Appointment.Description(new DateTime(2019, 03, 29, 15, 0, 0));
        // => "You have an appointment on 3/29/2019 3:00:00 PM."
        Appointment.AnniversaryDate();
        // => new DateTime(2019, 9, 15, 0, 0, 0)
    }

    public static DateTime Schedule(string appointmentDateDescription) => DateTime.Parse(appointmentDateDescription);

    public static bool HasPassed(DateTime appointmentDate) => (DateTime.Now > appointmentDate ? true : false);

    public static bool IsAfternoonAppointment(DateTime appointmentDate) => (appointmentDate.Hour >= 12 && appointmentDate.Hour < 18 ? true : false);

    public static string Description(DateTime appointmentDate) => $"You have an appointment on {appointmentDate.ToString()}.";

    public static DateTime AnniversaryDate() => new DateTime(DateTime.Now.Year, 9, 15, 0, 0, 0);

}
