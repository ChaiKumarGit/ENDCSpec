package chai.endc;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Vector;

import javax.xml.parsers.DocumentBuilderFactory;  
import javax.xml.parsers.DocumentBuilder;  
import org.w3c.dom.Document;  
import org.w3c.dom.NodeList;  
import org.w3c.dom.Node;  
import org.w3c.dom.Element;  
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class Parse {
	   
	
	private static final String CMDATTACHHEXTOPCAP = "\""+Data.wireSharkPath+"\\text2pcap.exe\" set_qANDl() attachHexData.txt attachTemp.pcap";
	private static final String CMDATTACHPCAPTOTXT = "\""+Data.wireSharkPath+ "\\tshark.exe\" -o \"set_uatUser()\\\"User 0 (DLT=147)\\\",\\\"<<CHANNEL>>\\\",\\\"0\\\",\\\"\\\",\\\"0\\\",\\\"\\\"\" -r attachTemp.pcap";
	private static final String CMDATTACHPCAPTOXML = "\""+Data.wireSharkPath+ "\\tshark.exe\" -o \"set_uatUser()\\\"User 0 (DLT=147)\\\",\\\"<<CHANNEL>>\\\",\\\"0\\\",\\\"\\\",\\\"0\\\",\\\"\\\"\" -r attachTemp.pcap";
	
	private static final String CMDUECPHEXTOPCAP = "\""+Data.wireSharkPath+"\\text2pcap.exe\" set_qANDl() ueCapHexData.txt ueCapTemp.pcap";
	private static final String CMDUECPHEXTOTXT = "\""+Data.wireSharkPath+ "\\tshark.exe\" -o \"set_uatUser()\\\"User 0 (DLT=147)\\\",\\\"<<CHANNEL>>\\\",\\\"0\\\",\\\"\\\",\\\"0\\\",\\\"\\\"\" -r ueCapTemp.pcap";
	private static final String CMDUECPHEXTOXML = "\""+Data.wireSharkPath+ "\\tshark.exe\" -o \"set_uatUser()\\\"User 0 (DLT=147)\\\",\\\"<<CHANNEL>>\\\",\\\"0\\\",\\\"\\\",\\\"0\\\",\\\"\\\"\" -r ueCapTemp.pcap";
	
	private static final String CMDUECPNRHEXTOPCAP = "\""+Data.wireSharkPath+"\\text2pcap.exe\" set_qANDl() ueNRCapHexData.txt ueNRCap.pcap";
	private static final String CMDUECPNRHEXTOTXT = "\""+Data.wireSharkPath+ "\\tshark.exe\" -o \"set_uatUser()\\\"User 0 (DLT=147)\\\",\\\"<<CHANNEL>>\\\",\\\"0\\\",\\\"\\\",\\\"0\\\",\\\"\\\"\" -r ueNRCap.pcap";
	private static final String CMDUECPNRHEXTOXML = "\""+Data.wireSharkPath+ "\\tshark.exe\" -o \"set_uatUser()\\\"User 0 (DLT=147)\\\",\\\"<<CHANNEL>>\\\",\\\"0\\\",\\\"\\\",\\\"0\\\",\\\"\\\"\" -r ueNRCap.pcap";
	
	private static Process process;    
	private static BufferedReader stdInput;
    private static BufferedReader stdError;
    private static String readOutput;
    
    public static int excelRow = 0;
    public static int excelCol = 0;
    
	static void convert() throws Exception {

		try (PrintWriter out = new PrintWriter("attachHexData.txt")) {
		    out.println(Data.attachHex);
		    out.flush();
		    out.close();
		}

		//Covert Attach Hex to PCAP
        // Run Windows command
         process = Runtime.getRuntime().exec(CMDATTACHHEXTOPCAP);

        // Get input streams
        stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
        stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));

        // Read command standard output    
        while ((readOutput = stdInput.readLine()) != null) {
            System.out.println(readOutput);
        }

        // Read command errors
        while ((readOutput = stdError.readLine()) != null) {
            System.out.println(readOutput);
        }
        process.destroy();
        stdInput.close();
        stdError.close();
        
        //Convert Attach PCAP to Text
        // Run Windows command            
        process = Runtime.getRuntime().exec(CMDATTACHPCAPTOTXT);
        
        // Get input streams
        stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
        stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
						
        // Read command standard output
        while ((readOutput = stdInput.readLine()) != null) {
            ENDCSpec.textPaneAttachDecoded.setText(ENDCSpec.textPaneAttachDecoded.getText()+"\n"+readOutput);
            
        }

        // Read command errors
        while ((readOutput = stdError.readLine()) != null) {
            ENDCSpec.textPaneAttachDecoded.setText(ENDCSpec.textPaneAttachDecoded.getText()+"\n"+readOutput);
            
        }
        process.destroy();
        stdInput.close();
        stdError.close();

        //Convert Attach PCAP to XML
        // Run Windows command            
        process = Runtime.getRuntime().exec(CMDATTACHPCAPTOXML);
        
        // Get input streams
        stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
        stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));

        // Read command standard output
		try (PrintWriter out = new PrintWriter("attach.xml")) {
			 while ((readOutput = stdInput.readLine()) != null) {
				 out.println(readOutput);
			 }
		    out.flush();
		    out.close();
		}
		
        // Read command errors
        while ((readOutput = stdError.readLine()) != null) {
            ENDCSpec.textPaneAttachDecoded.setText(readOutput);
        }
        process.destroy();
        stdInput.close();
        stdError.close();	
        
       // *********************************************************************************************
		
		try (PrintWriter out = new PrintWriter("ueCapHexData.txt")) {
		    out.println(Data.ueCapHex);
		    out.flush();
		    out.close();
		}


        //Covert UECAP Hex to PCAP
        // Run Windows command
         process = Runtime.getRuntime().exec(CMDUECPHEXTOPCAP);

        // Get input streams
        stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
        stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));

        // Read command standard output    
        while ((readOutput = stdInput.readLine()) != null) {
            System.out.println(readOutput);
        }

        // Read command errors
        while ((readOutput = stdError.readLine()) != null) {
            System.out.println(readOutput);
        }
        process.destroy();
        stdInput.close();
        stdError.close();
        
        //Convert UECAP PCAP to Text
        // Run Windows command            
        process = Runtime.getRuntime().exec(CMDUECPHEXTOTXT);
        
        // Get input streams
        stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
        stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));

        // Read command standard output
		try (PrintWriter out = new PrintWriter("uecap.txt")) {
            while ((readOutput = stdInput.readLine()) != null) {
            	out.println(readOutput);
               // LTESpec.textPaneUECapDecoded.setText( LTESpec.textPaneUECapDecoded.getText()+"\n"+readOutput);
                
            }
		    out.flush();
		    out.close();
		    
		    ENDCSpec.textPaneLTEUECapDecoded.setText( new String ( Files.readAllBytes( Paths.get("uecap.txt") ) ));
		}
		
        // Read command errors
        while ((readOutput = stdError.readLine()) != null) {
            ENDCSpec.textPaneLTEUECapDecoded.setText( ENDCSpec.textPaneLTEUECapDecoded.getText()+"\n"+readOutput);
            
        }
        process.destroy();
        stdInput.close();
        stdError.close();

        //Convert UECAP PCAP to XML
        // Run Windows command            
        process = Runtime.getRuntime().exec(CMDUECPHEXTOXML);
        
        // Get input streams
        stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
        stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));

        // Read command standard output
		try (PrintWriter out = new PrintWriter("ueLTECap.xml")) {
			 while ((readOutput = stdInput.readLine()) != null) {
				 out.println(readOutput);
			 }
		    out.flush();
		    out.close();
		}
		
        // Read command errors
        while ((readOutput = stdError.readLine()) != null) {
            ENDCSpec.textPaneLTEUECapDecoded.setText(readOutput);
        }
        process.destroy();
        stdInput.close();
        stdError.close();	

       // *********************************************************************************************

        try (PrintWriter out = new PrintWriter("ueNRCapHexData.txt")) {
			    out.println(Data.ueCapNRHex);
			    out.flush();
			    out.close();
			}


            //Covert UECAP Hex to PCAP
            // Run Windows command
             process = Runtime.getRuntime().exec(CMDUECPNRHEXTOPCAP);

            // Get input streams
            stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
            stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));

            // Read command standard output    
            while ((readOutput = stdInput.readLine()) != null) {
                System.out.println(readOutput);
            }

            // Read command errors
            while ((readOutput = stdError.readLine()) != null) {
                System.out.println(readOutput);
            }
            process.destroy();
            stdInput.close();
            stdError.close();
            
            //Convert UECAP PCAP to Text
            // Run Windows command            
            process = Runtime.getRuntime().exec(CMDUECPNRHEXTOTXT);
            
            // Get input streams
            stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
            stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));

            // Read command standard output
			try (PrintWriter out = new PrintWriter("ueNRCap.txt")) {
	            while ((readOutput = stdInput.readLine()) != null) {
	            	out.println(readOutput);
	               // LTESpec.textPaneUECapDecoded.setText( LTESpec.textPaneUECapDecoded.getText()+"\n"+readOutput);
	                
	            }
			    out.flush();
			    out.close();
			    
			    ENDCSpec.textPaneNRUECapDecoded.setText( new String ( Files.readAllBytes( Paths.get("ueNRCap.txt") ) ));
			}
			
            // Read command errors
            while ((readOutput = stdError.readLine()) != null) {
                ENDCSpec.textPaneNRUECapDecoded.setText( ENDCSpec.textPaneNRUECapDecoded.getText()+"\n"+readOutput);
                
            }
            process.destroy();
            stdInput.close();
            stdError.close();

            //Convert UECAP PCAP to XML
            // Run Windows command            
            process = Runtime.getRuntime().exec(CMDUECPNRHEXTOXML);
            
            // Get input streams
            stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
            stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));

            // Read command standard output
			try (PrintWriter out = new PrintWriter("ueNRCap.xml")) {
				 while ((readOutput = stdInput.readLine()) != null) {
					 out.println(readOutput);
				 }
			    out.flush();
			    out.close();
			}
			
            // Read command errors
            while ((readOutput = stdError.readLine()) != null) {
                ENDCSpec.textPaneNRUECapDecoded.setText(readOutput);
            }
            process.destroy();
            stdInput.close();
            stdError.close();	

           // *********************************************************************************************
	}
	
	static void parseXML() throws Exception {
			
		//Create Local Variables
	    File fXmlFile;
	    DocumentBuilderFactory dbFactory;
	    DocumentBuilder dBuilder;
	    Document doc;
	    NodeList nList;
	    Node nNode;
	    
		//Parsing attachRequest XML file  ****************************************************** 
	    fXmlFile = new File("attach.xml");
	    dbFactory = DocumentBuilderFactory.newInstance();
	    dBuilder = dbFactory.newDocumentBuilder();
	    doc = dBuilder.parse(fXmlFile);
	
	    doc.getDocumentElement().normalize();
	
	    nList = doc.getElementsByTagName("proto");
	    
	    for(int ieIndex = 0; ieIndex < Data.attachIEs.length ; ieIndex++) {
	        for (int protoItem = 0; protoItem < nList.getLength(); protoItem++) {
	             nNode = nList.item(protoItem);
	
	            if (nNode.getNodeType() == Node.ELEMENT_NODE) {
	                Element eElement = (Element) nNode;
	                if(eElement.getAttribute("name").contentEquals(Data.attachIEs[ieIndex][0])) {
	                	getElement(eElement, Data.attachIEs[ieIndex], ieIndex, 0, Data.searchArrayName.ATTACHIEs, 0);
	                }
	            }
	        }
	    }
	    
	    //EO- Parsing attachRequest XML file ******************************************************
	    
		
		//Parsing LTE UE Cap XML file  ****************************************************** 
	    fXmlFile = new File("ueLTECap.xml");
	    dbFactory = DocumentBuilderFactory.newInstance();
	    dBuilder = dbFactory.newDocumentBuilder();
	    doc = dBuilder.parse(fXmlFile);
	
	    doc.getDocumentElement().normalize();
	
	    nList = doc.getElementsByTagName("proto");
	    
	    for(int ieIndex = 0; ieIndex < Data.lteUECapIEs.length ; ieIndex++) {
	        for (int protoItem = 0; protoItem < nList.getLength(); protoItem++) {
	             nNode = nList.item(protoItem);
	
	            if (nNode.getNodeType() == Node.ELEMENT_NODE) {
	                Element eElement = (Element) nNode;
	                if(eElement.getAttribute("name").contentEquals(Data.lteUECapIEs[ieIndex][0])) {
	                	getElement(eElement, Data.lteUECapIEs[ieIndex], ieIndex, 0, Data.searchArrayName.LTEUECAPIEs, 0);
	                }
	            }
	        }
	    }
	    
	    //EO- Parsing LTE UE Cap XML file ******************************************************
	
		
		//Parsing NR UE Cap XML file  ****************************************************** 
	    fXmlFile = new File("ueNRCap.xml");
	    dbFactory = DocumentBuilderFactory.newInstance();
	    dBuilder = dbFactory.newDocumentBuilder();
	    doc = dBuilder.parse(fXmlFile);
	
	    doc.getDocumentElement().normalize();
	
	    nList = doc.getElementsByTagName("proto");
	    
	    for(int ieIndex = 0; ieIndex < Data.nrUECapIEs.length ; ieIndex++) {
	        for (int protoItem = 0; protoItem < nList.getLength(); protoItem++) {
	            	nNode = nList.item(protoItem);
	
	            if (nNode.getNodeType() == Node.ELEMENT_NODE) {
	                Element eElement = (Element) nNode;
	                if(eElement.getAttribute("name").contentEquals(Data.nrUECapIEs[ieIndex][0])) {
	                	getElement(eElement, Data.nrUECapIEs[ieIndex], ieIndex, 0, Data.searchArrayName.NRUECECAPIEs, 0);
	                }
	            }
	        }
	    }
	    
	    //EO- Parsing NR UE Cap XML file ******************************************************  
	    
	    getValue(Data.attachIEsElementList, Data.searchArrayName.ATTACHIEs);
	    getValue(Data.lteUECapIEsElementList, Data.searchArrayName.LTEUECAPIEs);
	    getValue(Data.nrUECapIEsElementList, Data.searchArrayName.NRUECECAPIEs);
	    
	}
	
	static void getElement(Element e, String[] msgIE, int msgIEIndex, int iePathIndex, Data.searchArrayName searchArrayName, int bandIndex) {
		iePathIndex++;
		String firstInList = msgIE[iePathIndex];
        NodeList children = e.getChildNodes();

            for (int i = 0; i < children.getLength(); i++) {
            	if (children.item(i).getNodeType() == Node.ELEMENT_NODE) {
                    Element subElement = (Element) children.item(i);
                    if(subElement.getAttribute("name").contentEquals(firstInList) && (iePathIndex < msgIE.length-1)) {
                        getElement(subElement, msgIE, msgIEIndex, iePathIndex, searchArrayName, bandIndex);
                    }
                    else if(subElement.getAttribute("name").contentEquals(firstInList) ) {
                    	if(searchArrayName == Data.searchArrayName.ATTACHIEs) {
                        	Data.attachIEsElementList.get(msgIEIndex).add(subElement);
                    	}
                    	else if(searchArrayName == Data.searchArrayName.LTEUECAPIEs) {
                        	Data.lteUECapIEsElementList.get(msgIEIndex).add(subElement);
                    	}
                    	else if(searchArrayName == Data.searchArrayName.NRUECECAPIEs) {
                        	Data.nrUECapIEsElementList.get(msgIEIndex).add(subElement);
                    	}
                    	else if(searchArrayName == Data.searchArrayName.BANDIEs) {
                        	Data.bandIEsElementList.get(bandIndex).get(msgIEIndex).add(subElement);
                    	}
                    }
                }
            }
	}
	
	static void getValue(List<List> Elements, Data.searchArrayName msgIEs) {
		
		if(msgIEs == Data.searchArrayName.ATTACHIEs) {
			for(int ieRowIndex=0; ieRowIndex<Data.attachIEs.length; ieRowIndex++) {
				for(int elementIndex=0; elementIndex<Data.attachIEsElementList.get(ieRowIndex).size(); elementIndex++) {
					for(int showNameColIndex=0; showNameColIndex<Data.attachIEsShowName[ieRowIndex].length; showNameColIndex++) {
						getShowVaueOfeachChileElement( ((Element)Data.attachIEsElementList.get(ieRowIndex).get(elementIndex)), Data.attachIEsShowName[ieRowIndex][showNameColIndex], ieRowIndex, showNameColIndex, Data.searchArrayName.ATTACHIEs, 0);
					}
				}
			}
		}
		else if(msgIEs == Data.searchArrayName.LTEUECAPIEs) {
			for(int ieRowIndex=0; ieRowIndex<Data.lteUECapIEs.length; ieRowIndex++) {
				for(int elementIndex=0; elementIndex<Data.lteUECapIEsElementList.get(ieRowIndex).size(); elementIndex++) {
					for(int showNameColIndex=0; showNameColIndex<Data.lteUECapIEsShowName[ieRowIndex].length; showNameColIndex++) {
						getShowVaueOfeachChileElement( ((Element)Data.lteUECapIEsElementList.get(ieRowIndex).get(elementIndex)), Data.lteUECapIEsShowName[ieRowIndex][showNameColIndex], ieRowIndex, showNameColIndex, Data.searchArrayName.LTEUECAPIEs, 0);
					}
				}
			}
		}
		else if(msgIEs == Data.searchArrayName.NRUECECAPIEs) {
			for(int ieRowIndex=0; ieRowIndex<Data.nrUECapIEs.length; ieRowIndex++) {
				for(int elementIndex=0; elementIndex<Data.nrUECapIEsElementList.get(ieRowIndex).size(); elementIndex++) {
					for(int showNameColIndex=0; showNameColIndex<Data.nrUECapIEsShowName[ieRowIndex].length; showNameColIndex++) {
						getShowVaueOfeachChileElement( ((Element)Data.nrUECapIEsElementList.get(ieRowIndex).get(elementIndex)), Data.nrUECapIEsShowName[ieRowIndex][showNameColIndex], ieRowIndex, showNameColIndex, Data.searchArrayName.NRUECECAPIEs, 0);
						
						//To fetch IEs from each NR band
						if(((Element)Data.nrUECapIEsElementList.get(ieRowIndex).get(elementIndex)).getAttribute("name").contentEquals("nr-rrc.supportedBandListNR")) {
							NodeList children = ((Element)Data.nrUECapIEsElementList.get(ieRowIndex).get(elementIndex)).getChildNodes();
							int childElementCount = 0;
							List<Element> childElements = new Vector<Element>();	
							
							for (int i = 0; i < children.getLength(); i++) {
				            	if (children.item(i).getNodeType() == Node.ELEMENT_NODE) {
				                    childElementCount++;
				                    childElements.add((Element)children.item(i));
				                }
				            }
							
							//Set empty bandIEValues
							Data.bandIEValues= new String[childElementCount][][][];
							
							for(int bandList =0; bandList < childElementCount; bandList++) {
								List<List<List>> emptyBandElement = new Vector<List<List>>();	
								Data.bandIEsElementList.add((List)emptyBandElement);
								
								for(int index=0; index<Data.bandIEs.length; index++) {
									List<List> empty = new Vector<List>();	
									Data.bandIEsElementList.get(bandList).add(empty);
								}
								
								Data.bandIEValues[bandList] = new String[Data.bandIEs.length][][];
								for(int bandIERowIndex =0; bandIERowIndex<Data.bandIEs.length; bandIERowIndex++) {
									Data.bandIEValues[bandList][bandIERowIndex] = new String[Data.bandIEsShowName[bandIERowIndex].length][];
									for(int colIndex =0; colIndex<Data.bandIEsShowName[bandIERowIndex].length; colIndex++) {
										Data.bandIEValues[bandList][bandIERowIndex][colIndex] = new String[1];
										Data.bandIEValues[bandList][bandIERowIndex][colIndex][0] = "No Information";
									}
								}			
							}
							
							//Get Elements of NR Band
						    for(int childIndex=0; childIndex<childElements.size(); childIndex++) {
							    for(int ieIndex = 0; ieIndex < Data.bandIEs.length ; ieIndex++) {
					                Element eElement = childElements.get(childIndex);
					                if(eElement.getAttribute("name").contains(Data.bandIEs[ieIndex][0])) {
					                	getElement(eElement, Data.bandIEs[ieIndex], ieIndex, 0, Data.searchArrayName.BANDIEs, childIndex);
					                }
							    }						    	
						    }
							
						    //Get Values from each NR Band Element
							for(int childIndex=0; childIndex<childElements.size(); childIndex++) {
								for(int bandIEShowNameRowIndex=0; bandIEShowNameRowIndex<Data.bandIEsShowName.length; bandIEShowNameRowIndex++) {
									for(int elementIndexBand=0; elementIndexBand<Data.bandIEsElementList.get(childIndex).get(bandIEShowNameRowIndex).size(); elementIndexBand++) {
										for(int showNameColIndexBand=0; showNameColIndexBand<Data.bandIEsShowName[bandIEShowNameRowIndex].length; showNameColIndexBand++) {
											getShowVaueOfeachChileElement( ((Element)Data.bandIEsElementList.get(childIndex).get(bandIEShowNameRowIndex).get(elementIndexBand)), Data.bandIEsShowName[bandIEShowNameRowIndex][showNameColIndexBand], bandIEShowNameRowIndex, showNameColIndexBand, Data.searchArrayName.BANDIEs, childIndex);
										}
									}
								}
							}
							
						}
					}
				}
			}
		}
	}
	
	static void getShowVaueOfeachChileElement(Element e, String searchStr, int rowIndex, int colIndex, Data.searchArrayName searchArrayName, int bandListIndex) {

        if(e.getAttribute("showname").contains(searchStr) ) {
        	if(searchArrayName == Data.searchArrayName.ATTACHIEs) {
        		//Increase Array Size
        		String[] temp= new String[Data.attachIEValues[rowIndex][colIndex].length + 1];
        		for (int i = 0; i < Data.attachIEValues[rowIndex][colIndex].length; i++){
			      temp[i] = Data.attachIEValues[rowIndex][colIndex][i];
        		}
        		Data.attachIEValues[rowIndex][colIndex] = temp;
			   //EO - Increase Array Size
        		
			   Data.attachIEValues[rowIndex][colIndex][Data.attachIEValues[rowIndex][colIndex].length - 2] = Excel_Util.getIEValue( Data.attachIEsShowName[rowIndex][colIndex], e.getAttribute("showname"), Data.attachIEsSkipStartChars[rowIndex][colIndex], Data.attachIEsEliminate[rowIndex][colIndex]);
        	}
        	else if(searchArrayName == Data.searchArrayName.LTEUECAPIEs) {
        		//Increase Array Size
        		String[] temp= new String[Data.lteUECapIEValues[rowIndex][colIndex].length + 1];
        		for (int i = 0; i < Data.lteUECapIEValues[rowIndex][colIndex].length; i++){
			      temp[i] = Data.lteUECapIEValues[rowIndex][colIndex][i];
        		}
        		Data.lteUECapIEValues[rowIndex][colIndex] = temp;
			   //EO - Increase Array Size
        		
			   Data.lteUECapIEValues[rowIndex][colIndex][Data.lteUECapIEValues[rowIndex][colIndex].length - 2] = Excel_Util.getIEValue( Data.lteUECapIEsShowName[rowIndex][colIndex], e.getAttribute("showname"), Data.lteUECapIEsSkipStartChars[rowIndex][colIndex], Data.lteUECapIEsEliminate[rowIndex][colIndex]);
        	}
        	else if(searchArrayName == Data.searchArrayName.NRUECECAPIEs) {
        		//Increase Array Size
        		String[] temp= new String[Data.nrUECapIEValues[rowIndex][colIndex].length + 1];
        		for (int i = 0; i < Data.nrUECapIEValues[rowIndex][colIndex].length; i++){
			      temp[i] = Data.nrUECapIEValues[rowIndex][colIndex][i];
        		}
        		Data.nrUECapIEValues[rowIndex][colIndex] = temp;
			   //EO - Increase Array Size
        		
			   Data.nrUECapIEValues[rowIndex][colIndex][Data.nrUECapIEValues[rowIndex][colIndex].length - 2] = Excel_Util.getIEValue( Data.nrUECapIEsShowName[rowIndex][colIndex], e.getAttribute("showname"), Data.nrUECapIEsSkipStartChars[rowIndex][colIndex], Data.nrUECapIEsEliminate[rowIndex][colIndex]);
        	}

        	else if(searchArrayName == Data.searchArrayName.BANDIEs) {
        		//Increase Array Size
        		String[] temp= new String[Data.bandIEValues[bandListIndex][rowIndex][colIndex].length + 1];
        		for (int i = 0; i < Data.bandIEValues[bandListIndex][rowIndex][colIndex].length; i++){
			      temp[i] = Data.bandIEValues[bandListIndex][rowIndex][colIndex][i];
        		}
        		Data.bandIEValues[bandListIndex][rowIndex][colIndex] = temp;
			   //EO - Increase Array Size			
        		
        		Data.bandIEValues[bandListIndex][rowIndex][colIndex][Data.bandIEValues[bandListIndex][rowIndex][colIndex].length - 2] = Excel_Util.getIEValue( Data.bandIEsShowName[rowIndex][colIndex], e.getAttribute("showname"), Data.bandIEsSkipStartChars[rowIndex][colIndex], Data.bandIEsEliminate[rowIndex][colIndex]);
        	}
        }
        
		NodeList children = e.getChildNodes();

            for (int i = 0; i < children.getLength(); i++) {
            	if (children.item(i).getNodeType() == Node.ELEMENT_NODE) {
                    Element subElement = (Element) children.item(i);
                    getShowVaueOfeachChileElement(subElement, searchStr, rowIndex, colIndex, searchArrayName, bandListIndex);
                }
            }
	}

	static void writeToExcel() throws Exception {

		Excel_Util.createExcel("ENDC"+ Excel_Util.getJustTime()+".xls");
			
			for(String ie : Data.userIIEs) {
	  			Excel_Util.writeToSheet(ie, excelRow, 1);
				Parse.excelRow++;
			}
			Excel_Util.writeToSheet(Excel_Util.getDate(), 1, 2);
			
			//Write Attach IE to Excel
			for(int rowIndex=0; rowIndex < Data.attachIEsExcelName.length; rowIndex++){
				for(int colIndex=0; colIndex < Data.attachIEsExcelName[rowIndex].length; colIndex++) {
		  			Excel_Util.writeToSheet(Data.attachIEsExcelName[rowIndex][colIndex], Parse.excelRow, 1);
		  			
		  			String mergeArray="";
		  			for(int mergeArrayIndex=0; mergeArrayIndex<Data.attachIEValues[rowIndex][colIndex].length -1; mergeArrayIndex++) {
		  				if(mergeArrayIndex > 0) {
			  				mergeArray += ", "+Data.attachIEValues[rowIndex][colIndex][mergeArrayIndex];
		  				}
		  				else {
		  					mergeArray += Data.attachIEValues[rowIndex][colIndex][mergeArrayIndex];
		  				}
		  			}
					Excel_Util.writeToSheet(mergeArray, excelRow, 2);
					Parse.excelRow++;
				}
			}

			//Write LTE UE Cap IE to Excel
			for(int rowIndex=0; rowIndex < Data.lteUECapIEsExcelName.length; rowIndex++){
				for(int colIndex=0; colIndex < Data.lteUECapIEsExcelName[rowIndex].length; colIndex++) {
		  			Excel_Util.writeToSheet(Data.lteUECapIEsExcelName[rowIndex][colIndex], Parse.excelRow, 1);
		  			
		  			String mergeArray="";
		  			for(int mergeArrayIndex=0; mergeArrayIndex<Data.lteUECapIEValues[rowIndex][colIndex].length -1; mergeArrayIndex++) {
		  				if(mergeArrayIndex > 0) {
			  				mergeArray += ", "+Data.lteUECapIEValues[rowIndex][colIndex][mergeArrayIndex];
		  				}
		  				else {
		  					mergeArray += Data.lteUECapIEValues[rowIndex][colIndex][mergeArrayIndex];
		  				}
		  			}
					Excel_Util.writeToSheet(mergeArray, excelRow, 2);
					Parse.excelRow++;
				}
			}

			//Write NR UE Cap IE to Excel
			for(int rowIndex=0; rowIndex < Data.nrUECapIEsExcelName.length; rowIndex++){
				for(int colIndex=0; colIndex < Data.nrUECapIEsExcelName[rowIndex].length; colIndex++) {
		  			Excel_Util.writeToSheet(Data.nrUECapIEsExcelName[rowIndex][colIndex], Parse.excelRow, 1);
		  			
		  			String mergeArray="";
		  			for(int mergeArrayIndex=0; mergeArrayIndex<Data.nrUECapIEValues[rowIndex][colIndex].length -1; mergeArrayIndex++) {
		  				if(mergeArrayIndex > 0) {
			  				mergeArray += ", "+Data.nrUECapIEValues[rowIndex][colIndex][mergeArrayIndex];
		  				}
		  				else {
		  					mergeArray += Data.nrUECapIEValues[rowIndex][colIndex][mergeArrayIndex];
		  				}
		  			}
					Excel_Util.writeToSheet(mergeArray, excelRow, 2);
					Parse.excelRow++;
				}
			} 
			
			//Write NR Band IE to Excel
			for(int bandListIndex=0; bandListIndex < Data.bandIEValues.length; bandListIndex++) {
				for(int rowIndex=0; rowIndex < Data.bandIEValues[bandListIndex].length; rowIndex++){
					for(int colIndex=0; colIndex < Data.bandIEsExcelName[rowIndex].length; colIndex++) {
						Excel_Util.writeToSheet(Data.bandIEsExcelName[rowIndex][colIndex], Parse.excelRow, 1);
			  			
						String mergeArray="";
			  			for(int mergeArrayIndex=0; mergeArrayIndex<Data.bandIEValues[bandListIndex][rowIndex][colIndex].length -1; mergeArrayIndex++) {
			  				if(mergeArrayIndex > 0) {
				  				mergeArray += ", "+Data.bandIEValues[bandListIndex][rowIndex][colIndex][mergeArrayIndex];
			  				}
			  				else {
			  					mergeArray += Data.bandIEValues[bandListIndex][rowIndex][colIndex][mergeArrayIndex];
			  				}
			  			}
						Excel_Util.writeToSheet(mergeArray, excelRow, 2);
						Parse.excelRow++;
					}
				} 
			}
			
			Excel_Util.closeExcel();
	}

}
