gdbus-codegen --interface-prefix org.tizen.telephony. \
	--generate-c-code generated-code                        \
	--c-namespace Telephony                       \
	--c-generate-object-manager                 \
	--generate-docbook generated-docs                       \
	manager.xml network.xml sim.xml phonebook.xml sat.xml sap.xml gps.xml oem.xml modem.xml ss.xml call.xml sms.xml
