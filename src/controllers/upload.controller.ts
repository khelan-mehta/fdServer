import { Controller, Post, Body, Param } from '@nestjs/common';
import { UserService } from '../services/user.service';

@Controller('upload-excels/')
export class ExcelUploadController {
  constructor(private readonly userService: UserService) {}

  @Post(':id')
  async uploadExcelData(
    @Param('id') id: string, @Body() body: { file1Data: any[]; file2Data: any[] }
  ) {
    const { file1Data, file2Data } = body;
    console.log(id);
    
    

    // Process both files and check discrepancies
    const discrepancies = await this.userService.compareExcelData(
      file1Data,
      file2Data
    );

    return { success: true, discrepancies };
  }
}
