
# Parallels DaaS (Desktop-as-a-Service)

Parallels DaaS is a cloud-native, Desktop-as-a-Service (DaaS) solution that offers users secure, instant access to their virtual applications and desktops. This repository contains a script that configures all prerequisites in Azure in an automated way. 



## Installation
> Step 1: [Running the script](./1.runscript.md)

> Step 2: [Completing the Azure Subscription wizard](./2.completewizard.md)



## Summary
Below is a summary of the actions that the script performs.

- Create the App Registration
- Create a new Client Secret
- Create an Azure Key Vault and securely store the Client Secret in it
- Set the Graph API permissions (user.read.all & group.read.all) for the App Registration
- Set User Access Administrator permissions on subscription level for the App Registration
- Add VM Reader permission on subscription to support standalone host pools & custom images
- Create a resource group for the Parallels DaaS infrastructure components
- Create a resource gruop for the Parallels DaaS session hosts 
- Add contributor permissions on the resource group for the App Registration
- Add contributor permissions on the vNet for the App Registration 
- Output all values the admin needs to complete the Parallels DaaS getting started & connect to Microsoft Azure wizard


## Support 

If you have comments or suggestions, we encourage you to send us feedback.
You can do this from Parallels DaaS Management Portal:
Click the "person" icon in the top-right corner.
From the menu that opens, select Provide Feedback.
Add your feedback and click Send.
You can also send feedback to our dedicated support address cloud-beta@support.parallels.com.


## Documentation

- [Admin guide](https://docs.myparallels.com/parallels-daas-administrators-guide/)

- [Getting started guide](https://docs.myparallels.com/parallels-daas-administrators-guide/gettings-started)

- [User guide](https://docs.myparallels.com/parallels-daas-users-guide/)
## License 

The scripts are MIT-licensed, so you are free to use it in your commercial setting.

