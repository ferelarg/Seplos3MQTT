#!/usr/bin/env python

"""
Seplos BMSv3 to MQTT
---------------------------------------------------------------------------


"""
# --------------------------------------------------------------------------- #
# import the various needed libraries
# --------------------------------------------------------------------------- #
import signal
import sys
import logging
import serial
import configparser
import paho.mqtt.client as mqtt

# --------------------------------------------------------------------------- #
# configure the logging system
# --------------------------------------------------------------------------- #
class myFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            self._style._fmt = "%(asctime)-15s %(message)s"
        elif record.levelno == logging.DEBUG:
            self._style._fmt = f"%(asctime)-15s \033[36m%(levelname)-8s\033[0m: %(message)s"
        else:
            color = {
                logging.WARNING: 33,
                logging.ERROR: 31,
                logging.FATAL: 31,
            }.get(record.levelno, 0)
            self._style._fmt = f"%(asctime)-15s \033[{color}m%(levelname)-8s %(threadName)-15s-%(module)-15s:%(lineno)-8s\033[0m: %(message)s"
        return super().format(record)

log = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(myFormatter())
log.setLevel(logging.INFO)
log.addHandler(handler)

# --------------------------------------------------------------------------- #
# declare the sniffer
# --------------------------------------------------------------------------- #
class SerialSnooper:

    def __init__(self, port, mqtt_server, mqtt_port, mqtt_user, mqtt_pass):
        self.port = port
        self.data = bytearray(0)
        self.trashdata = False
        self.trashdataf = bytearray(0)
        self.batts_declared_set = set()
        # init the signal handler for a clean exit
        signal.signal(signal.SIGINT, self.signal_handler)

        log.info(f"Opening serial interface, port: {port} 19200 8N1 timeout: 0.001750")
        self.connection = serial.Serial(port=port, baudrate=19200, bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, timeout=0.001750)
        log.debug(self.connection)
       
        self.mqtt_hass = mqtt.Client()
        self.mqtt_hass.username_pw_set(username=mqtt_user, password=mqtt_pass)
        try:
            log.info(f"Opening MQTT connection, server: {mqtt_server}\tport: {mqtt_port}")
            self.mqtt_hass.connect(mqtt_server, mqtt_port) 
        except ConnectionRefusedError:
            print("Error: Unable to connect to MQTT server.")
        except Exception as e:
            print(f"MQTT Unexpected error: {str(e)}")


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self):
        self.connection.open()

    def close(self):
        self.connection.close()
    
    def read_raw(self, n=1):
        return self.connection.read(n)
    
    # --------------------------------------------------------------------------- #
    # configure a clean exit (even with the use of kill, 
    # may be useful if saving the data to a file)
    # --------------------------------------------------------------------------- #
    def signal_handler(self, sig, frame):
        for batt_number in self.batts_declared_set:
            log.info(f"Sending offline signal for Battery {batt_number}")
            self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{batt_number}/state", "offline", retain=True)
        print('\nGoodbye\n')
        sys.exit(0)
    
    def to_lower_under(self, text):
        text = text.lower()
        text = text.replace(' ', '_')
        return text


    # --------------------------------------------------------------------------- #
    # Bufferise the data and call the decoder if the interframe timeout occur.
    # --------------------------------------------------------------------------- #
    def process_data(self, data):
        if len(data) <= 0:
            if len(self.data) > 2:
                self.data = self.decodeModbus(self.data)
            return
        for dat in data:
            self.data.append(dat)
    
    def autodiscovery_battery (self, unitIdentifier):
        log.info(f"Sending autodiscovery block Battery {unitIdentifier}")
        #Pack Main
        self.autodiscovery_sensor ( "voltage","measurement", "V", "Pack Voltage", unitIdentifier)
        self.autodiscovery_sensor ( "current","measurement", "A", "Current", unitIdentifier)
        self.autodiscovery_sensor ( "","measurement", "Ah", "Remaining Capacity", unitIdentifier)
        self.autodiscovery_sensor ( "","measurement", "Ah", "Total Capacity", unitIdentifier)
        self.autodiscovery_sensor ( "","measurement", "Ah", "Total Discharge Capacity", unitIdentifier)
        self.autodiscovery_sensor ( "","measurement", "%", "SOC", unitIdentifier)
        self.autodiscovery_sensor ( "","measurement", "%", "SOH", unitIdentifier)
        self.autodiscovery_sensor ( "","measurement", "cycles", "Cycles", unitIdentifier)
        self.autodiscovery_sensor ( "voltage","measurement", "V", "Average Cell Voltage", unitIdentifier)
        self.autodiscovery_sensor ( "temperature","measurement", "°C", "Average Cell Temp", unitIdentifier)
        self.autodiscovery_sensor ( "voltage","measurement", "V", "Max Cell Voltage", unitIdentifier)
        self.autodiscovery_sensor ( "voltage","measurement", "V", "Min Cell Voltage", unitIdentifier)
        self.autodiscovery_sensor ( "temperature","measurement", "°C", "Max Cell Temp", unitIdentifier)
        self.autodiscovery_sensor ( "temperature","measurement", "°C", "Min Cell Temp", unitIdentifier)
        self.autodiscovery_sensor ( "current","measurement", "A", "MaxDisCurt", unitIdentifier)
        self.autodiscovery_sensor ( "current","measurement", "A", "MaxChgCurt", unitIdentifier)
        self.autodiscovery_sensor ( "power","measurement", "W", "Power", unitIdentifier)
        self.autodiscovery_sensor ( "voltage","measurement", "mV", "Cell Delta", unitIdentifier)

        #Pack Cells
        for i in range(1, 17):
            self.autodiscovery_sensor ( "voltage","measurement", "V", f"Cell {i}", unitIdentifier)

        #Pack Status and Alarm
        self.autodiscovery_sensor ( "","", "", "Status", unitIdentifier)
        self.autodiscovery_sensor ( "","", "", "TB09", unitIdentifier)
        self.autodiscovery_sensor ( "","", "", "TB02", unitIdentifier)
        self.autodiscovery_sensor ( "","", "", "TB03", unitIdentifier)
        self.autodiscovery_sensor ( "","", "", "TB04", unitIdentifier)
        self.autodiscovery_sensor ( "","", "", "TB05", unitIdentifier)
        self.autodiscovery_sensor ( "","", "", "TB16", unitIdentifier)
        self.autodiscovery_sensor ( "","", "", "TB06", unitIdentifier)
        self.autodiscovery_sensor ( "","", "", "TB07", unitIdentifier)
        self.autodiscovery_sensor ( "","", "", "TB08", unitIdentifier)
        self.autodiscovery_sensor ( "","", "", "TB15", unitIdentifier)
        
        log.info(f"Sending online signal for Battery {unitIdentifier}")
        self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/state", "online", retain=True)

    def autodiscovery_sensor (self, dev_cla, state_class, sensor_unit, sensor_name, batt_number):
        
        name_under = self.to_lower_under (sensor_name)
        if dev_cla != "": dev_cla = f""" "dev_cla": "{dev_cla}", """
        if state_class != "": state_class = f""" "stat_cla": "{state_class}", """
        if sensor_unit != "": sensor_unit = f""" "unit_of_meas": "{sensor_unit}", """

        mqtt_packet = f"""
                        {{	 
                            "name": "{sensor_name}",
                            "stat_t": "{mqtt_prefix}/battery_{batt_number}/{name_under}",
                            "avty_t": "{mqtt_prefix}/battery_{batt_number}/state",
                            "uniq_id": "seplos_battery_{batt_number}_{name_under}",
                            {dev_cla}
                            {sensor_unit}
                            {state_class}
                            "dev": {{
                                "ids": "seplos_battery_{batt_number}",
                                "name": "Seplos BMS {batt_number}",
                                "sw": "seplos3mqtt 1.0",
                                "mdl": "Seplos BMSv3 MQTT",
                                "mf": "Domotica Solar"
                                }},
                            "origin": {{
                                "name":"seplos3mqtt by Domotica Solar",
                                "sw": "1.0",
                                "url": "https://domotica.solar/"
                            }}
                        }}
                        """
        self.mqtt_hass.publish(f"homeassistant/sensor/seplos_bms_{batt_number}/{name_under}/config", mqtt_packet, retain=True)

    # --------------------------------------------------------------------------- #
    # Debuffer and decode the modbus frames (Request, Responce, Exception)
    # --------------------------------------------------------------------------- #
    def decodeModbus(self, data):
        modbusdata = data
        bufferIndex = 0
        
        while True:
            unitIdentifier = 0
            functionCode = 0
            readByteCount = 0
            readData = bytearray(0)
            crc16 = 0
            responce = False
            needMoreData = False
            frameStartIndex = bufferIndex           
            if len(modbusdata) > (frameStartIndex + 2):
                # Unit Identifier (Slave Address)
                unitIdentifier = modbusdata[bufferIndex]
                bufferIndex += 1
                # Function Code
                functionCode = modbusdata[bufferIndex]
                bufferIndex += 1
                if functionCode == 1:
                    # Responce size: UnitIdentifier (1) + FunctionCode (1) + ReadByteCount (1) + ReadData (n) + CRC (2)
                    expectedLenght = 7 # 5 + n (n >= 2)
                    if len(modbusdata) >= (frameStartIndex + expectedLenght):
                        bufferIndex = frameStartIndex + 2
                        # Read Byte Count (1)
                        readByteCount = modbusdata[bufferIndex]
                        bufferIndex += 1
                        expectedLenght = (5 + readByteCount)
                        if len(modbusdata) >= (frameStartIndex + expectedLenght):
                            # Read Data (n)
                            index = 1
                            while index <= readByteCount:
                                readData.append(modbusdata[bufferIndex])
                                bufferIndex += 1
                                index += 1
                            # CRC16 (2)
                            crc16 = (modbusdata[bufferIndex] * 0x0100) + modbusdata[bufferIndex + 1]
                            metCRC16 = self.calcCRC16(modbusdata, bufferIndex)
                            bufferIndex += 2
                            if crc16 == metCRC16:
                                if self.trashdata:
                                    self.trashdata = False
                                    self.trashdataf += "]"
                                    #log.info(self.trashdataf)
                                responce = True

                                #### Pack Alarms and Status ###
                                if readByteCount == 18:   
                                    if unitIdentifier not in self.batts_declared_set:
                                        self.autodiscovery_battery(unitIdentifier)
                                        self.batts_declared_set.add(unitIdentifier)

                                    strStatus = "" 
                                    if   (readData[8] >> 0) & 1: strStatus = "Discharge"
                                    elif (readData[8] >> 1) & 1: strStatus = "Charge"
                                    elif (readData[8] >> 2) & 1: strStatus = "Floating charge"
                                    elif (readData[8] >> 3) & 1: strStatus = "Full charge"
                                    elif (readData[8] >> 4) & 1: strStatus = "Standby mode"
                                    elif (readData[8] >> 5) & 1: strStatus = "Turn off"

                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/status", strStatus, retain=True)
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/tb09", readData[8], retain=True)
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/tb02", readData[9], retain=True)
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/tb03", readData[10], retain=True)
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/tb04", readData[11], retain=True)
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/tb05", readData[12], retain=True)
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/tb16", readData[13], retain=True)
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/tb06", readData[14], retain=True)
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/tb07", readData[15], retain=True)
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/tb08", readData[16], retain=True)
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/tb15", readData[17], retain=True)

                                modbusdata = modbusdata[bufferIndex:]
                                bufferIndex = 0
                        else:
                            needMoreData = True
                    else:
                        needMoreData = True
                # FC03 (0x03) Read Holding Registers  FC04 (0x04) Read Input Registers
                elif functionCode == 4:
                    # Responce size: UnitIdentifier (1) + FunctionCode (1) + ReadByteCount (1) + ReadData (n) + CRC (2)
                    expectedLenght = 7 # 5 + n (n >= 2)
                    if len(modbusdata) >= (frameStartIndex + expectedLenght):
                        bufferIndex = frameStartIndex + 2
                        # Read Byte Count (1)
                        readByteCount = modbusdata[bufferIndex]
                        bufferIndex += 1
                        expectedLenght = (5 + readByteCount)
                        if len(modbusdata) >= (frameStartIndex + expectedLenght):
                            # Read Data (n)
                            index = 1
                            while index <= readByteCount:
                                readData.append(modbusdata[bufferIndex])
                                bufferIndex += 1
                                index += 1
                            # CRC16 (2)
                            crc16 = (modbusdata[bufferIndex] * 0x0100) + modbusdata[bufferIndex + 1]
                            metCRC16 = self.calcCRC16(modbusdata, bufferIndex)
                            bufferIndex += 2
                            if crc16 == metCRC16:
                                if self.trashdata:
                                    self.trashdata = False
                                    self.trashdataf += "]"
                                    # log.info(self.trashdataf)
                                responce = True

                                # Cell Pack information #######################################
                                celdas = {}
                                if readByteCount == 52:   
                                    celda = 0
                                    ## HASS Autodiscovery 
                                    if unitIdentifier not in self.batts_declared_set:
                                        self.autodiscovery_battery(unitIdentifier)
                                        self.batts_declared_set.add(unitIdentifier)

                                    for i in range(0, 32, 2):
                                        celda =  (((readData[i] << 8) | readData[i + 1]) / 1000.0)
                                        self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/cell_{int(i/2)+1}", celda, retain=True)

                                # Pack Main information #######################################
                                if readByteCount == 36:   
                                    readDataNumber = []

                                    for i in range(0, 36, 2):
                                        readDataNumber.append((readData[i] << 8) | readData[i + 1])
                                    # HASS autodiscovery MQTT    
                                    if unitIdentifier not in self.batts_declared_set:
                                        self.autodiscovery_battery(unitIdentifier)
                                        self.batts_declared_set.add(unitIdentifier)

                                    # Pack Voltage
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/pack_voltage", readDataNumber[0]/100.0, retain=True)
                                    # Current
                                    current_decimal = readDataNumber [1] if readDataNumber [1] <= 32767 else readDataNumber [1] - 65536
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/current", current_decimal/100.0, retain=True)
                                    # Remaining Capacity
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/remaining_capacity", readDataNumber[2]/100.0, retain=True)
                                    # Total Capacity
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/total_capacity", readDataNumber[3]/100.0, retain=True)
                                    # Total Discharge Capacity
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/total_discharge_capacity", readDataNumber[4]*10, retain=True)
                                    # SOC
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/soc", readDataNumber[5]/10.0, retain=True)
                                    # SOH
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/soh", readDataNumber[6]/10.0, retain=True)
                                    # Cycles
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/cycles", readDataNumber[7], retain=True)
                                    # Average Cell Voltage
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/average_cell_voltage", readDataNumber[8]/1000.0, retain=True)
                                    # Average Cell Temp
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/average_cell_temp", round ((readDataNumber[9]/10 - 273.15) ,1), retain=True)
                                    # Max Cell Voltage
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/max_cell_voltage", readDataNumber[10]/1000.0, retain=True)
                                    # Min Cell Voltage
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/min_cell_voltage", readDataNumber[11]/1000.0, retain=True)
                                    # Max Cell Temp
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/max_cell_temp", round ((readDataNumber[12]/10 - 273.15),1), retain=True)
                                    # Min Cell Temp
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/min_cell_temp", round ((readDataNumber[13]/10 - 273.15),1), retain=True)
                                    # Reserve readDataNumber [14]
                                    # MaxDisCurt
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/maxdiscurt", readDataNumber[15], retain=True)
                                    # MaxChgCurt
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/maxchgcurt", readDataNumber[16], retain=True)        
                                    #Calculated Power end Delta
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/power", int(-(current_decimal/100.0)*(readDataNumber[0]/100.0)), retain=True)
                                    self.mqtt_hass.publish(f"{mqtt_prefix}/battery_{unitIdentifier}/cell_delta", int((readDataNumber[10]) - (readDataNumber[11])), retain=True)

                                modbusdata = modbusdata[bufferIndex:]
                                bufferIndex = 0
                        else:
                            needMoreData = True
                    else:
                        needMoreData = True
            else:
                needMoreData = True

            if needMoreData:
                return modbusdata
            elif  (responce == False):
                if self.trashdata:
                    self.trashdataf += " {:02x}".format(modbusdata[frameStartIndex])
                else:
                    self.trashdata = True
                    self.trashdataf = "Ignoring data: [{:02x}".format(modbusdata[frameStartIndex])
                bufferIndex = frameStartIndex + 1
                modbusdata = modbusdata[bufferIndex:]
                bufferIndex = 0

    # --------------------------------------------------------------------------- #
    # Calculate the modbus CRC
    # --------------------------------------------------------------------------- #
    def calcCRC16(self, data, size):
        crcHi = 0XFF
        crcLo = 0xFF
        
        crcHiTable	= [	0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
                        0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                        0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
                        0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
                        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
                        0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
                        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
                        0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
                        0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
                        0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
                        0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
                        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
                        0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
                        0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
                        0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
                        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
                        0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                        0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
                        0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                        0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
                        0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
                        0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
                        0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
                        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
                        0x80, 0x41, 0x00, 0xC1, 0x81, 0x40]

        crcLoTable = [  0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06,
                        0x07, 0xC7, 0x05, 0xC5, 0xC4, 0x04, 0xCC, 0x0C, 0x0D, 0xCD,
                        0x0F, 0xCF, 0xCE, 0x0E, 0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09,
                        0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9, 0x1B, 0xDB, 0xDA, 0x1A,
                        0x1E, 0xDE, 0xDF, 0x1F, 0xDD, 0x1D, 0x1C, 0xDC, 0x14, 0xD4,
                        0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12, 0x13, 0xD3,
                        0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3,
                        0xF2, 0x32, 0x36, 0xF6, 0xF7, 0x37, 0xF5, 0x35, 0x34, 0xF4,
                        0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A,
                        0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 0x28, 0xE8, 0xE9, 0x29,
                        0xEB, 0x2B, 0x2A, 0xEA, 0xEE, 0x2E, 0x2F, 0xEF, 0x2D, 0xED,
                        0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26,
                        0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60,
                        0x61, 0xA1, 0x63, 0xA3, 0xA2, 0x62, 0x66, 0xA6, 0xA7, 0x67,
                        0xA5, 0x65, 0x64, 0xA4, 0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F,
                        0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB, 0x69, 0xA9, 0xA8, 0x68,
                        0x78, 0xB8, 0xB9, 0x79, 0xBB, 0x7B, 0x7A, 0xBA, 0xBE, 0x7E,
                        0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5,
                        0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71,
                        0x70, 0xB0, 0x50, 0x90, 0x91, 0x51, 0x93, 0x53, 0x52, 0x92,
                        0x96, 0x56, 0x57, 0x97, 0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C,
                        0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E, 0x5A, 0x9A, 0x9B, 0x5B,
                        0x99, 0x59, 0x58, 0x98, 0x88, 0x48, 0x49, 0x89, 0x4B, 0x8B,
                        0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C,
                        0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42,
                        0x43, 0x83, 0x41, 0x81, 0x80, 0x40]

        index = 0
        while index < size:
            crc = crcHi ^ data[index]
            crcHi = crcLo ^ crcHiTable[crc]
            crcLo = crcLoTable[crc]
            index += 1

        metCRC16 = (crcHi * 0x0100) + crcLo
        return metCRC16

# --------------------------------------------------------------------------- #
# Print the usage help
# --------------------------------------------------------------------------- #
def printHelp():
    print("\nUsage:")
    print("  python seplos3mqtt.py")
    print("")
    print("Seplos3mqtt gets the configuration from seplos3mqtt.ini")
    print("Remember to create the file and include the following data:")
    print("[seplos3mqtt]")
    print("serial = ")
    print("mqtt_server = ")
    print("mqtt_port = ")
    print("mqtt_user = ")
    print("mqtt_pass = ")
    print("mqtt_prefix = ")
    print("")



# --------------------------------------------------------------------------- #
# main routine
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    print(" ")

    config = configparser.ConfigParser()

    try:
        config.read('seplos3mqtt.ini')
        port = config.get('seplos3mqtt', 'serial')
        mqtt_server = config.get('seplos3mqtt', 'mqtt_server')
        mqtt_port = int(config.get('seplos3mqtt', 'mqtt_port'))
        mqtt_user = config.get('seplos3mqtt', 'mqtt_user')
        mqtt_pass = config.get('seplos3mqtt', 'mqtt_pass')
        mqtt_prefix = config.get('seplos3mqtt', 'mqtt_prefix')
        

        with SerialSnooper(port,mqtt_server, mqtt_port, mqtt_user, mqtt_pass) as sniffer:
            while True:
                data = sniffer.read_raw()
                sniffer.process_data(data)
    except configparser.NoSectionError as e:
        print("Error: Section [seplos3mqtt] not found in the file seplos3mqtt.ini")
        printHelp()
    except configparser.NoOptionError as e:
        print(f'Error: Missing a parameter in the file seplos3mqtt.ini Details: {e}')
        printHelp()
    except FileNotFoundError as e:
        print("Error: seplos3mqtt.ini was not found.")
        printHelp()
    except Exception as e:
        print(f'Unexpected error: {e}')
        printHelp()

#Master: ID: 3, Read Input Registers: 0x04, Read address: 4096, Read Quantity: 18 //Pack Main information
#Slave:  ID: 3, Read Input Registers: 0x04, Read byte count: 36, Read data: [14 94 f4 c9 56 f4 6d 60 01 a6 03 1b 03 e5 00 1a 0c dc 0b 7d 0c de 0c d9 0b 80 0b 77 00 00 00 46 00 46 03 e8]
#Master: ID: 3, Read Input Registers: 0x04, Read address: 4352, Read Quantity: 26 //Pack Cells information
#Slave:  ID: 3, Read Input Registers: 0x04, Read byte count: 52, Read data: [0c dd 0c dd 0c dd 0c dc 0c dd 0c dd 0c dc 0c dc 0c d9 0c dc 0c dd 0c de 0c de 0c dd 0c dc 0c de 0b 7e 0b 80 0b 77 0b 80 0a ab 0a ab 0a ab 0a ab 0b 81 0b 6b]
#Master: ID: 3, Read Coils: 0x01, Read address: 4608, Read Quantity: 144 //Pack Alarms and Status
#Slave:  ID: 3, Read Coils: 0x01, Read byte count: 18, Read data: [00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 03 00 00]
