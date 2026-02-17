import { Module } from '@nestjs/common';
import { TellerController } from './teller.controller';
import { TellerService } from './teller.service';

@Module({
  controllers: [TellerController],
  providers: [TellerService]
})
export class TellerModule {}
