package chai.endc;

import java.util.List;
import java.util.Vector;

import org.w3c.dom.Element;

public class Data {
	
	
	private static final String HEXTOPCAP = getPCAP();
	private static final String PCAPTOJSON = WrapperPCAP(Parse.convert());
	
	static final String version = "(V1.1)";
	static final String appName = "ENDCSpec";
	static final String newLine = "\\r\\n|\\r|\\n";
	static final String hexStartBits = "0000 ";
	
	static String wireSharkPath = "C:\\Program Files\\Wireshark";
	static String attachHex;
	static String ueCapHex;
	static String ueCapNRHex;
	
	static enum searchArrayName {ATTACHIEs, LTEUECAPIEs, NRUECECAPIEs, BANDIEs};
	
	//User interaction IEs
	static final String[] userIIEs = {
			"Tester",
			"Date",
			"Manufacturer",
			"Device/Model",
			"Firmware",
			"Chipset",
			"RadioStack/AMSS version",
			"RRC Release",
			"Pre-IOT = Partial coverage",
			"Default APN",
			"Default APN Authentication Type",
			"SVN / Test Cycle (IOT-X/MR-X): "
	};
	
	//Attach Request IEs
	static final String[][] attachIEs = {
			{"nas-eps",""}
	};

	static final String[][] attachIEsShowName = {
			{
			"Dual connectivity with NR: ",
			"PDN type: ",
			"EEA0: ",
			"128-EEA1: ",
			"128-EEA2: ",
			"128-EEA3: ",
			"EIA0: ",
			"128-EIA1: ",
			"128-EIA2: ",
			"128-EIA3: ",
			"5G-EA0: ",
			"128-5G-EA1: ",
			"128-5G-EA2: ",
			"128-5G-EA3: ",
			"5G-IA0: ",
			"128-5G-IA1: ",
			"128-5G-IA2: ",
			"128-5G-IA3: "
			}
	};
	
	static final String[][] attachIEsExcelName = {
			{
			"Dual connectivity with NR: ",
			"PDN type: ",
			"EEA0: ",
			"128-EEA1: ",
			"128-EEA2: ",
			"128-EEA3: ",
			"EIA0: ",
			"128-EIA1: ",
			"128-EIA2: ",
			"128-EIA3: ",
			"5G-EA0: ",
			"128-5G-EA1: ",
			"128-5G-EA2: ",
			"128-5G-EA3: ",
			"5G-IA0: ",
			"128-5G-IA1: ",
			"128-5G-IA2: ",
			"128-5G-IA3: "
			}
	};
	
	static final int[][] attachIEsEliminate = {
		{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	};
	static final int[][] attachIEsSkipStartChars = {
		{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	};
	static List <List> attachIEsElementList = new Vector<List>();
	static String[][][] attachIEValues = new String[attachIEs.length][][];
	
	//EO- Attach Request IEs
	
	//LTE UE Cap
	static final String[][] lteUECapIEs = {
			{"fake-field-wrapper","lte-rrc.UL_DCCH_Message_element","lte-rrc.message","lte-rrc.c1","lte-rrc.ueCapabilityInformation_element","lte-rrc.criticalExtensions","lte-rrc.c1","lte-rrc.ueCapabilityInformation_r8_element"}
	};

	static final String[][] lteUECapIEsShowName = {
			{"bandNR-r15: "}
	};
	
	static final String[][] lteUECapIEsExcelName = {
			{"Supported NR Band"}
	};
	
	static final int[][] lteUECapIEsEliminate = {
			{0}
	};
	static final int[][] lteUECapIEsSkipStartChars = {
			{0}
	};
	static List <List> lteUECapIEsElementList = new Vector<List>();
	static String[][][] lteUECapIEValues = new String[lteUECapIEs.length][][];
	
	//EO- LTE UE Cap

	
	//NR UE Cap
	static final String[][] nrUECapIEs = {
			{"fake-field-wrapper","lte-rrc.UL_DCCH_Message_element"},
			{"fake-field-wrapper","lte-rrc.UL_DCCH_Message_element"},
			{"fake-field-wrapper","lte-rrc.UL_DCCH_Message_element"},
			{"fake-field-wrapper", "lte-rrc.UL_DCCH_Message_element", "lte-rrc.message", "lte-rrc.c1", "lte-rrc.ueCapabilityInformation_element", "lte-rrc.criticalExtensions", "lte-rrc.c1", "lte-rrc.ueCapabilityInformation_r8_element", "lte-rrc.ue_CapabilityRAT_ContainerList", "", "lte-rrc.UE_CapabilityRAT_Container_element", "lte-rrc.ueCapabilityRAT_Container", "nr-rrc.UE_NR_Capability_element", "nr-rrc.rf_Parameters_element", "nr-rrc.supportedBandListNR"}
	};

	static final String[][] nrUECapIEsShowName = {
			{"profile0x0000:","profile0x0001: ","profile0x0002: ","profile0x0003: ","profile0x0004: ","profile0x0006: ","profile0x0101: ","profile0x0102: ","profile0x0103: ","profile0x0104: ","maxNumberROHC-ContextSessions: "},
			{"am-WithShortSN: ","um-WithShortSN: ","um-WithLongSN: ", "skipUplinkTxDynamic: ", "logicalChannelSR-DelayTimer: ", "longDRX-Cycle: ", "shortDRX-Cycle: ", "multipleSR-Configurations: ", "multipleConfiguredGrants: "},
			{"twoFL-DMRS: ","supportedDMRS-TypeDL: ","supportedDMRS-TypeUL: ","csi-ReportWithoutPMI: ","pucch-F2-WithFH: ","pucch-F3-WithFH: ","absoluteTPC-Command: ","pusch-HalfPi-BPSK: ","oneFL-DMRS-TwoAdditionalDMRS-UL: ","twoFL-DMRS-TwoAdditionalDMRS-UL: ","pdsch-256QAM-FR1: ","rateMatchingResrcSetSemi-Static: "},
			{"supportedBandListNR:"}//Do not add more IE in this Row
	};
	
	static final String[][] nrUECapIEsExcelName = {
			{"profile0x0000: ","profile0x0001: ","profile0x0002: ","profile0x0003: ","profile0x0004: ","profile0x0006: ","profile0x0101: ","profile0x0102: ","profile0x0103: ","profile0x0104: ","maxNumberROHC-ContextSessions: "},
			{"rlc-Parameters-> am-WithShortSN: ","rlc-Parameters-> um-WithShortSN: ","rlc-Parameters-> um-WithLongSN: ", "mac-ParametersXDD-Diff-> skipUplinkTxDynamic: ", "mac-ParametersXDD-Diff-> logicalChannelSR-DelayTimer: ", "mac-ParametersXDD-Diff-> longDRX-Cycle: ", "mac-ParametersXDD-Diff-> shortDRX-Cycle: ", "mac-ParametersXDD-Diff-> multipleSR-Configurations: ", "mac-ParametersXDD-Diff-> multipleConfiguredGrants: "},
			{"phy-ParametersFRX-Diff-> twoFL-DMRS: ","phy-ParametersFRX-Diff-> supportedDMRS-TypeDL: ","phy-ParametersFRX-Diff-> supportedDMRS-TypeUL: ","phy-ParametersFRX-Diff-> csi-ReportWithoutPMI: ","phy-ParametersFRX-Diff-> pucch-F2-WithFH: ","phy-ParametersFRX-Diff-> pucch-F3-WithFH: ","phy-ParametersFRX-Diff-> absoluteTPC-Command: ","phy-ParametersFRX-Diff-> pusch-HalfPi-BPSK: ","phy-ParametersFRX-Diff-> oneFL-DMRS-TwoAdditionalDMRS-UL: ","phy-ParametersFRX-Diff-> twoFL-DMRS-TwoAdditionalDMRS-UL: ","phy-ParametersFR1-> pdsch-256QAM-FR1: ","rateMatchingResrcSetSemi-Static (DSS): "},
			{"supportedBandListNR"}
	};
	
	static final int[][] nrUECapIEsSkipStartChars = {
			{0,0,0,0,0,0,0,0,0,0,0},
			{0,0,0,0,0,0,0,0,0},
			{0,0,0,0,0,0,0,0,0,0,0,0},
			{0}
	};
	static final int[][] nrUECapIEsEliminate = {
			{0,0,0,0,0,0,0,0,0,0,3},
			{3,3,3,3,3,3,3,3,3},
			{3,3,3,3,3,3,3,3,3,3,3,3},
			{0}
	};

	static List <List> nrUECapIEsElementList = new Vector<List>();
	static String[][][] nrUECapIEValues = new String[nrUECapIEs.length][][];
	
	//Search repeatedly for below IES in supported band list for 'n' number of times. [where 'n' is number of NR bands supported by UE]
	static final String[][] bandIEs= {
			{"","nr-rrc.BandNR_element"},
			{"","nr-rrc.BandNR_element","nr-rrc.mimo_ParametersPerBand_element"},
			{"","nr-rrc.BandNR_element","nr-rrc.mimo_ParametersPerBand_element","nr-rrc.periodicBeamReport"},
			{"","nr-rrc.BandNR_element","nr-rrc.mimo_ParametersPerBand_element","nr-rrc.maxNumberRxTxBeamSwitchDL_element"},
			{"","nr-rrc.BandNR_element","nr-rrc.mimo_ParametersPerBand_element","nr-rrc.beamReportTiming_element"},
			{"","nr-rrc.BandNR_element","nr-rrc.mimo_ParametersPerBand_element"},
			{"","nr-rrc.BandNR_element"},
			{"","nr-rrc.BandNR_element","nr-rrc.channelBWs_DL_v1530"},
			{"","nr-rrc.BandNR_element","nr-rrc.channelBWs_UL_v1530"},
			{"","nr-rrc.BandNR_element"}
	};
	
	static final String[][] bandIEsShowName = {
			{"bandNR: ","mimo-ParametersPerBand is "},
			{"maxNumberConfiguredTCIstatesPerCC: ","maxNumberActiveTCI-PerBWP: ","pusch-TransCoherence: ","aperiodicBeamReport: ","maxNumberNonGroupBeamReporting: ","maxNumberCSI-RS-SSB-CBD: "},
			{"periodicBeamReport: "},
			{"scs-15kHz: ","scs-30kHz: ","scs-60kHz: ","scs-120kHz: ","scs-240kHz: "},
			{"scs-15kHz: ","scs-30kHz: ","scs-60kHz: ","scs-120kHz: "},
			{"maxNumberSSB-CSI-RS-ResourceOneTx: ","maxNumberCSI-RS-Resource: ","maxNumberCSI-RS-ResourceTwoTx: ","supportedCSI-RS-Density: ","maxNumberAperiodicCSI-RS-Resource: ","supportedCSI-RS-ResourceList: ","maxNumberTxPortsPerResource: ","maxNumberResourcesPerBand: ","totalNumberTxPortsPerBand: ","modes: ","maxNumberCSI-RS-PerResourceSet: "},
			{"multipleTCI: ","pusch-256QAM: ","ue-PowerClass: "},
			{"scs-15kHz: ","scs-30kHz: ","scs-60kHz: ","scs-120kHz: "},
			{"scs-15kHz: ","scs-30kHz: ","scs-60kHz: ","scs-120kHz: "},
			{"maxUplinkDutyCycle-PC2-FR1: ","powerBoosting-pi2BPSK: ","rateMatchingLTE-CRS: "}
	};
	
	static final String[][] bandIEsExcelName = {
			{"NR Band ","MIMO ParametersPerBand"},
			{"maxNumberConfiguredTCIstatesPerCC ","maxNumberActiveTCI-PerBWP ","pusch-TransCoherence ","aperiodicBeamReport ","maxNumber Non Group Beam Reporting ","maxNumberCSI-RS-SSB-CBD "},
			{"periodicBeamReport "},
			{"maxNumberRxTxBeamSwitchDL-> scs-15kHz: ","maxNumberRxTxBeamSwitchDL-> scs-30kHz: ","maxNumberRxTxBeamSwitchDL-> scs-60kHz: ","maxNumberRxTxBeamSwitchDL-> scs-120kHz: ","maxNumberRxTxBeamSwitchDL-> scs-240kHz: "},
			{"beamReportTiming -> scs-15kHz: ","beamReportTiming -> scs-30kHz: ","beamReportTiming -> scs-60kHz: ","beamReportTiming -> scs-120kHz: "},
			{"maxNumberSSB-CSI-RS-ResourceOneTx: ","maxNumberCSI-RS-Resource: ","maxNumberCSI-RS-ResourceTwoTx: ","supportedCSI-RS-Density: ","maxNumberAperiodicCSI-RS-Resource: ","codebookParameters (Type1 singlePanel) -> supportedCSI-RS-ResourceList: ","codebookParameters (Type1 singlePanel) -> maxNumberTxPortsPerResource: ","codebookParameters (Type1 singlePanel) -> maxNumberResourcesPerBand: ","codebookParameters (Type1 singlePanel) -> totalNumberTxPortsPerBand: ","codebookParameters (Type1 singlePanel) -> modes: ","codebookParameters (Type1 singlePanel) -> maxNumberCSI-RS-PerResourceSet: "},
			{"multipleTCI: ","pusch-256QAM: ","ue-PowerClass: "},
			{"channelBWsDL ( FR1: 5,10,15,20,25,30,40,50,60 and 80MHz | FR2: 50,100 and 200MHz) -> scs-15kHz: ","channelBWsDL ( FR1: 5,10,15,20,25,30,40,50,60 and 80MHz | FR2: 50,100 and 200MHz) -> scs-30kHz: ","channelBWsDL ( FR1: 5,10,15,20,25,30,40,50,60 and 80MHz | FR2: 50,100 and 200MHz) -> scs-60kHz: ","channelBWsDL ( FR1: 5,10,15,20,25,30,40,50,60 and 80MHz | FR2: 50,100 and 200MHz) -> scs-120kHz: "},
			{"channelBWsUL ( FR1: 5,10,15,20,25,30,40,50,60 and 80MHz | FR2: 50,100 and 200MHz) -> scs-15kHz: ","channelBWsUL ( FR1: 5,10,15,20,25,30,40,50,60 and 80MHz | FR2: 50,100 and 200MHz) -> scs-30kHz: ","channelBWsUL ( FR1: 5,10,15,20,25,30,40,50,60 and 80MHz | FR2: 50,100 and 200MHz) -> scs-60kHz: ","channelBWsUL ( FR1: 5,10,15,20,25,30,40,50,60 and 80MHz | FR2: 50,100 and 200MHz) -> scs-120kHz: "},
			{"maxUplinkDutyCycle-PC2-FR1: ","powerBoosting-pi2BPSK: ", "rateMatchingLTE-CRS: "}
	};
	static final int[][] bandIEsSkipStartChars = {
			{0,0},
			{0,0,0,0,0,0},
			{0},
			{0,0,0,0,0},
			{0,0,0,0},
			{0,0,0,0,0,0,0,0,0,0,0},
			{0,0,0},
			{3,3,3,3},
			{3,3,3,3},
			{0,0,0}
	};
	static final int[][] bandIEsEliminate = {
			{0,1},
			{3,3,3,3,3,0},
			{3},
			{3,3,3,3,3},
			{3,3,3,3},
			{3,3,3,3,3,0,3,0,0,3,0},
			{3,3,3},
			{0,0,0,0},
			{0,0,0,0},
			{3,3,3}
	};
	
	static List <List<List>> bandIEsElementList = new Vector<List<List>>();
	static String[][][][] bandIEValues;
	
	//EO- NR UE Cap
	
	static void createElementList() {
		//Attach Request
		for(int index=0; index<attachIEs.length; index++) {
			List<Element> empty = new Vector<Element>();	
			attachIEsElementList.add(empty);
		}
		
		for(int index =0; index<attachIEValues.length; index++) {
			attachIEValues[index] = new String[attachIEsShowName[index].length][];
			for(int rowIndex =0; rowIndex<attachIEValues[index].length; rowIndex++) {
				attachIEValues[index][rowIndex] = new String[1];
				attachIEValues[index][rowIndex][0] = "No Information";
			}
		}
		
		//lte UE Cap
		for(int index=0; index<lteUECapIEs.length; index++) {
			List<Element> empty = new Vector<Element>();	
			lteUECapIEsElementList.add(empty);
		}
		
		for(int index =0; index<lteUECapIEValues.length; index++) {
			lteUECapIEValues[index] = new String[lteUECapIEsShowName[index].length][];
			for(int rowIndex =0; rowIndex<lteUECapIEValues[index].length; rowIndex++) {
				lteUECapIEValues[index][rowIndex] = new String[1];
				lteUECapIEValues[index][rowIndex][0] = "No Information";
			}
		}
		
		//nr UE Cap
		for(int index=0; index<nrUECapIEs.length; index++) {
			List<Element> empty = new Vector<Element>();	
			nrUECapIEsElementList.add(empty);
		}
		
		for(int index =0; index<nrUECapIEValues.length; index++) {
			nrUECapIEValues[index] = new String[nrUECapIEsShowName[index].length][];
			for(int rowIndex =0; rowIndex<nrUECapIEValues[index].length; rowIndex++) {
				nrUECapIEValues[index][rowIndex] = new String[1];
				nrUECapIEValues[index][rowIndex][0] = "No Information";
			}
		}

	}

}
