package chai.endc;
import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.BorderStyle;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.FillPatternType;
import org.apache.poi.ss.usermodel.Font;
import org.apache.poi.ss.usermodel.HorizontalAlignment;
import org.apache.poi.ss.usermodel.IndexedColors;
import org.apache.poi.ss.usermodel.Row; 
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.VerticalAlignment;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.util.CellRangeAddress; 
public class Excel_Util {
	// For a workbook instances 
	static Workbook wb; 
	static FileOutputStream os; 
	// For a sheet 
	static Sheet sheet; 
	
	
	//Font And Style
	private static Font defaultFont;
	private static CellStyle styleDefault;
	
	private static Font fontBoldBlueVerdana;
	private static CellStyle styleBoldBlueVerdana;
	
	private static Font verticalAlignFont1;
	private static CellStyle styleVerticalAlign1;
	
	private static Font verticalAlignFont2;
	private static CellStyle styleVerticalAlign2;
	
	private static Font verticalAlignFont3;
	private static CellStyle styleVerticalAlign3;	
	
	
	static void createFontNStyle() {
		
		
		defaultFont = wb.createFont();
		defaultFont.setBold(false);
	         
	    styleDefault = wb.createCellStyle();
	    styleDefault.setFont(defaultFont);
	    styleDefault.setAlignment(HorizontalAlignment.RIGHT);
	    styleDefault.setVerticalAlignment(VerticalAlignment.CENTER);
//	    styleDefault.setFillPattern(FillPatternType.SOLID_FOREGROUND);
	    styleDefault.setBorderRight(BorderStyle.THIN);
	    styleDefault.setRightBorderColor(IndexedColors.BLACK.getIndex());
	    styleDefault.setBorderLeft(BorderStyle.THIN);
	    styleDefault.setLeftBorderColor(IndexedColors.BLACK.getIndex());
	    styleDefault.setBorderTop(BorderStyle.THIN);
	    styleDefault.setTopBorderColor(IndexedColors.BLACK.getIndex());
	    styleDefault.setBorderBottom(BorderStyle.THIN);
	    styleDefault.setBottomBorderColor(IndexedColors.BLACK.getIndex());
	    
		
		fontBoldBlueVerdana = wb.createFont();
		fontBoldBlueVerdana.setFontName("VERDANA");
		fontBoldBlueVerdana.setColor(IndexedColors.CORNFLOWER_BLUE.getIndex());
		fontBoldBlueVerdana.setBold(true);
		
	    styleBoldBlueVerdana = wb.createCellStyle();
	    styleBoldBlueVerdana.setFont(fontBoldBlueVerdana);
	    //style.setWrapText(true);
	    styleBoldBlueVerdana.setAlignment(HorizontalAlignment.LEFT);
	    styleBoldBlueVerdana.setVerticalAlignment(VerticalAlignment.CENTER);
	    styleBoldBlueVerdana.setFillForegroundColor(IndexedColors.LIGHT_TURQUOISE.getIndex());
	    styleBoldBlueVerdana.setFillPattern(FillPatternType.SOLID_FOREGROUND);
	    styleBoldBlueVerdana.setBorderRight(BorderStyle.THIN);
	    styleBoldBlueVerdana.setRightBorderColor(IndexedColors.BLACK.getIndex());
	    styleBoldBlueVerdana.setBorderLeft(BorderStyle.THIN);
	    styleBoldBlueVerdana.setLeftBorderColor(IndexedColors.BLACK.getIndex());
	    styleBoldBlueVerdana.setBorderTop(BorderStyle.THIN);
	    styleBoldBlueVerdana.setTopBorderColor(IndexedColors.BLACK.getIndex());
	    styleBoldBlueVerdana.setBorderBottom(BorderStyle.THIN);
	    styleBoldBlueVerdana.setBottomBorderColor(IndexedColors.BLACK.getIndex());
	 
	    
	    verticalAlignFont1 = wb.createFont();
	    verticalAlignFont1.setFontName("VERDANA");
	    verticalAlignFont1.setColor(IndexedColors.BLACK.getIndex());
	    verticalAlignFont1.setBold(true);
		
	    styleVerticalAlign1 = wb.createCellStyle();
	    styleVerticalAlign1.setFont(verticalAlignFont1);
	    styleVerticalAlign1.setAlignment(HorizontalAlignment.CENTER);
	    styleVerticalAlign1.setVerticalAlignment(VerticalAlignment.CENTER);
	    styleVerticalAlign1.setFillForegroundColor(IndexedColors.LIGHT_GREEN.getIndex());
	    styleVerticalAlign1.setFillPattern(FillPatternType.SOLID_FOREGROUND);
	    styleVerticalAlign1.setBorderRight(BorderStyle.THIN);
	    styleVerticalAlign1.setRightBorderColor(IndexedColors.BLACK.getIndex());
	    styleVerticalAlign1.setBorderLeft(BorderStyle.THIN);
	    styleVerticalAlign1.setLeftBorderColor(IndexedColors.BLACK.getIndex());
	    styleVerticalAlign1.setBorderTop(BorderStyle.THIN);
	    styleVerticalAlign1.setTopBorderColor(IndexedColors.BLACK.getIndex());
	    styleVerticalAlign1.setBorderBottom(BorderStyle.THIN);
	    styleVerticalAlign1.setBottomBorderColor(IndexedColors.BLACK.getIndex());
	    styleVerticalAlign1.setRotation((short)90);
	    
	    
	    verticalAlignFont2 = wb.createFont();
	    verticalAlignFont2.setFontName("VERDANA");
	    verticalAlignFont2.setColor(IndexedColors.BLACK.getIndex());
	    verticalAlignFont2.setBold(true);
		
	    styleVerticalAlign2 = wb.createCellStyle();
	    styleVerticalAlign2.setFont(verticalAlignFont2);
	    styleVerticalAlign2.setAlignment(HorizontalAlignment.CENTER);
	    styleVerticalAlign2.setVerticalAlignment(VerticalAlignment.CENTER);
	    styleVerticalAlign2.setFillForegroundColor(IndexedColors.LIGHT_ORANGE.getIndex());
	    styleVerticalAlign2.setFillPattern(FillPatternType.SOLID_FOREGROUND);
	    styleVerticalAlign2.setBorderRight(BorderStyle.THIN);
	    styleVerticalAlign2.setRightBorderColor(IndexedColors.BLACK.getIndex());
	    styleVerticalAlign2.setBorderLeft(BorderStyle.THIN);
	    styleVerticalAlign2.setLeftBorderColor(IndexedColors.BLACK.getIndex());
	    styleVerticalAlign2.setBorderTop(BorderStyle.THIN);
	    styleVerticalAlign2.setTopBorderColor(IndexedColors.BLACK.getIndex());
	    styleVerticalAlign2.setBorderBottom(BorderStyle.THIN);
	    styleVerticalAlign2.setBottomBorderColor(IndexedColors.BLACK.getIndex());
	    styleVerticalAlign2.setRotation((short)90);	    
	    
	    verticalAlignFont3 = wb.createFont();
	    verticalAlignFont3.setFontName("VERDANA");
	    verticalAlignFont3.setColor(IndexedColors.BLACK.getIndex());
	    verticalAlignFont3.setBold(true);
		
	    styleVerticalAlign3 = wb.createCellStyle();
	    styleVerticalAlign3.setFont(verticalAlignFont3);
	    styleVerticalAlign3.setAlignment(HorizontalAlignment.CENTER);
	    styleVerticalAlign3.setVerticalAlignment(VerticalAlignment.CENTER);
	    styleVerticalAlign3.setFillForegroundColor(IndexedColors.LIGHT_YELLOW.getIndex());
	    styleVerticalAlign3.setFillPattern(FillPatternType.SOLID_FOREGROUND);
	    styleVerticalAlign3.setBorderRight(BorderStyle.THIN);
	    styleVerticalAlign3.setRightBorderColor(IndexedColors.BLACK.getIndex());
	    styleVerticalAlign3.setBorderLeft(BorderStyle.THIN);
	    styleVerticalAlign3.setLeftBorderColor(IndexedColors.BLACK.getIndex());
	    styleVerticalAlign3.setBorderTop(BorderStyle.THIN);
	    styleVerticalAlign3.setTopBorderColor(IndexedColors.BLACK.getIndex());
	    styleVerticalAlign3.setBorderBottom(BorderStyle.THIN);
	    styleVerticalAlign3.setBottomBorderColor(IndexedColors.BLACK.getIndex());
	    styleVerticalAlign3.setRotation((short)90);
	}
	
	
	
	static void createExcel(String fileName)throws FileNotFoundException, IOException{
		// Create a workbook instances 
		wb = new HSSFWorkbook(); 
		os = new FileOutputStream(fileName); 
		// Creating a sheet using predefined class provided by Apache POI 
		sheet = wb.createSheet("ENDC Spec"); 
		
		createFontNStyle();
	}

	static void writeToSheet (String stringToinsert, int rowIndex, int columnIndex)throws IOException
	{ 
		Row row;
		Cell cell;
        
		 
		// Creating a row at specific position 
		// using predefined class provided by Apache POI 
		// Specific row number 
		if((row = sheet.getRow(rowIndex)) == null) {
			row = sheet.createRow(rowIndex); 
		}
		// Specific cell number 
		if((cell = row.getCell(columnIndex)) == null) {
			cell = row.createCell(columnIndex);
			
		}
		
		// putting value at specific position 
		cell.setCellValue(stringToinsert); 
		
		
		if(columnIndex == 1) {
			cell.setCellStyle(styleBoldBlueVerdana);
		}else {
			cell.setCellStyle(styleDefault);
		}

	} 
	
	static String getIEValue(String ie, String value, int skipStartChars,int skipFromEnd) {
		String tmpRValue="";
		int startIndex = value.indexOf(ie);
		if(startIndex!=-1) {
			tmpRValue = value.substring(startIndex + ie.length() +skipStartChars, (value.length()-skipFromEnd));
			
			if(tmpRValue != null && tmpRValue.length() > 0 && tmpRValue.charAt(tmpRValue.length() - 1) == '"') {
				tmpRValue = tmpRValue.substring(0, tmpRValue.length()-1);
			}
		}
		return tmpRValue;
		
	}
	
	static void closeExcel() throws IOException{

		updateAndMerge();

		// Resize all columns to fit the content size
        for(int i = 1; i < 3; i++) {
            sheet.autoSizeColumn(i);
        }
        
		// writing the content to Workbook 
		wb.write(os); 
		
		wb.close();
		os.close();
	}
	
	static void updateAndMerge() throws IOException {
		
		Row row;
		Cell cell;
		    
		// Creating a row at specific position referring to starting position of User Interaction IE Row
		if((row = sheet.getRow(0)) == null) {
			row = sheet.createRow(0); 
		}
		// Specific cell number 
		if((cell = row.getCell(0)) == null) {
			cell = row.createCell(0);
			
		}
		
		// putting value at specific position 
		cell.setCellValue("Device Information"); 
		//Apply style
		cell.setCellStyle(styleVerticalAlign1);
		//Merge Cells
		sheet.addMergedRegion(CellRangeAddress.valueOf("A1:A12"));
		
		//**********
		// Creating a row at specific position referring to starting position of Attach Request IE Row
		if((row = sheet.getRow(Data.userIIEs.length)) == null) {
			row = sheet.createRow(Data.userIIEs.length); 
		}
		// Specific cell number 
		if((cell = row.getCell(0)) == null) {
			cell = row.createCell(0);
		}
		
		// putting value at specific position 
		cell.setCellValue("Attach Request"); 
		cell.setCellStyle(styleVerticalAlign2);
		
		//Merge Cells
		int attachIeCount=0;
		for(int IeCountIndex=0; IeCountIndex < Data.attachIEsExcelName.length; IeCountIndex++) {
			for(int eachIeInRow=0; eachIeInRow < Data.attachIEsExcelName[IeCountIndex].length; eachIeInRow++) {
				attachIeCount++;
			}
		}
		sheet.addMergedRegion(new CellRangeAddress( Data.userIIEs.length , (Data.userIIEs.length + attachIeCount -1),0,0));
		
		//**********
		// Creating a row at specific position referring to starting position of UE Capability IE Row
		if((row = sheet.getRow((Data.userIIEs.length + attachIeCount))) == null) {
			row = sheet.createRow((Data.userIIEs.length + attachIeCount)); 
		}
		// Specific cell number 
		if((cell = row.getCell(0)) == null) {
			cell = row.createCell(0);
		}
		
		// putting value at specific position 
		cell.setCellValue("UE Capabilities"); 
		cell.setCellStyle(styleVerticalAlign3);
		
		//Merge Cells
		int ueCapIeCount=0;
		for(int ueCapIeCountIndex=0; ueCapIeCountIndex < Data.lteUECapIEsExcelName.length; ueCapIeCountIndex++) {
			for(int eachIeInRow=0; eachIeInRow < Data.lteUECapIEsExcelName[ueCapIeCountIndex].length; eachIeInRow++) {
				ueCapIeCount++;
			}
		}
		for(int ueCapIeCountIndex=0; ueCapIeCountIndex < Data.nrUECapIEsExcelName.length; ueCapIeCountIndex++) {
			for(int eachIeInRow=0; eachIeInRow < Data.nrUECapIEsExcelName[ueCapIeCountIndex].length; eachIeInRow++) {
				ueCapIeCount++;
			}
		}
		for(int bandIeCountIndex=0; bandIeCountIndex < Data.bandIEValues.length; bandIeCountIndex++) {
			for(int eachIeInRow=0; eachIeInRow < Data.bandIEValues[bandIeCountIndex].length; eachIeInRow++) {
				for(int eachIeInCol=0; eachIeInCol < Data.bandIEValues[bandIeCountIndex][eachIeInRow].length; eachIeInCol++) {
					ueCapIeCount++;
				}
			}
		}
		
		sheet.addMergedRegion(new CellRangeAddress( (Data.userIIEs.length + attachIeCount) , ((Data.userIIEs.length + attachIeCount + ueCapIeCount) -1),0,0));
		
	}
	static String getDate() {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");  
		LocalDateTime now = LocalDateTime.now();  
		return dtf.format(now);
	}
	
	static String getJustTime() {
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("HHmmss");  
		LocalDateTime now = LocalDateTime.now();  
		return dtf.format(now);
	}
}


