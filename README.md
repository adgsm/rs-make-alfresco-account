# Alfresco Authentication AMP, including missing reset password functionality

Comperhensive library for authentication against Alfresco including missing functionalities like reset password and reset password request via email

### Usage

#### Create AMP
```
mvn clean install
```
#### Install AMP
```
/opt/alfresco/bin/apply_amps.sh
```
or
```
java -jar /opt/alfresco/bin/alfresco-mmt.jar install rs-make-alfresco-account /opt/alfresco/tomcat/webapps/alfresco.war
```

### License
Licensed under the MIT license.
http://www.opensource.org/licenses/mit-license.php
