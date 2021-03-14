# <u> GENERIC API </u>
The project is to create the most generic api

## <u> Framework </u>
I use .NET 5

## <u> Installation </u>

### <u> SQL SERVER </u>
You need to create a SQL Server Database and register is connection string in Api\appsettings.json and replace the value of DefaultConnection by your connection string. This is the way to do it if u need help : <br>
https://www.c-sharpcorner.com/UploadFile/d40a40/get-sql-server-database-connection-string-easily-from-visual/#:~:text=Right%2Dclick%20on%20your%20connection,use%20it%20anywhere%20you%20want.

You need to set "Api" as default project to launch in visual studio
Open the Package Manager Console and write Update-Database

### <u> SendGRID </u>
#### <u> Development Environment </u>
This api need SendGrid for send email, if u wan't to change the way to send email the method is in ServiceFolder\Services\MessageServices : SendEmailAsync

If you wan't to use SendGRID follow this step use the services. 
Go to this link and create an free account https://sendgrid.com. <br>
When you arrived on the welcome page click on Create a Single Sender <br>
You must fill in the following information : <br>
FROM NAME : The name for the email who will send the email for the app <br>
From email address and replay to : The email who will send the email for the app<br>
Compagny Adress, City, Country, Nickname : Your information  <br>
Create the email sender and go to the box of the email and verify the email with the email sendgrid send to you. <br>
Then replace the value of **SENDGRID_EMAIL** in Api\Properties\launchSettings.json by the email use for create the Single Sender <br>

After this click on Setting > Api Key > Create an API Key <br>
You must fill in the following information : <br>
API Key Name : The name for your key <br>
In permission select Restricted and allow only Mail Send and create the key. 
COPY THE KEY and replace the value of **SENDGRID_APIKEY** in Api\Properties\launchSettings.json <br>

#### <u> Production Environment </u>
You can follow the following microsoft docs : https://docs.microsoft.com/fr-fr/azure/sendgrid-dotnet-how-to-send-email <br>
COPY THE KEY and replace the value of **SENDGRID_APIKEY** in Api\Properties\launchSettings.json <br>
Then replace the value of **SENDGRID_EMAIL** in Api\Properties\launchSettings.json by the email use for send email<br>


### <u> Test </u>
To test the API you can download postman : https://www.postman.com <br>
Then import the postman collection Generic-Api.postman_collection.json <br>
If you need help for import a collection un postman : https://learning.postman.com/docs/getting-started/importing-and-exporting-data