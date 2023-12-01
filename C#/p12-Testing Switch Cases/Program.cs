/*
int employeeLevel = 200;
string employeeName = "John Smith";

string title = "";

switch (employeeLevel)
{
    case 100:
        title = "Junior Associate";
        break;
    case 200:
        title = "Senior Associate";
        break;
    case 300:
        title = "Manager";
        break;
    case 400:
        title = "Senior Manager";
        break;
    default:
        title = "Associate";
        break;
}

Console.WriteLine($"{employeeName}, {title}");
*/

//string sku = "01-MN-L";

Console.WriteLine("Enter your SKU");
string sku = Console.ReadLine();
string[] product = sku.Split('-');

string type = "";
string color = "";
string size = "";


switch (product[0])
{
	case "01":
		type = "Sweat Shirt";
		break;
	case "02":
		type = "T-Shirt";
		break;
	case "03":
		type = "Sweat Pants";
		break;
	default:
		type = "Other";
		break;
}

switch (product[1])
{
	case "BL":
		color = "Black";
		break;
	case "MN":
		color = "Maroon";
		break;
	default:
		color = "White";
		break;
}

switch (product[2])
{
	case "S":
		size = "Small";
		break;
	case "M":
		size = "Medium";
		break;
	case "L":
		size = "Large";
		break;
	default:
		size = "One Size Fits All";
		break;
}

Console.WriteLine($"Product: {size} {color} {type}");