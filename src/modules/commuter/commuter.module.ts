import { Module } from '@nestjs/common';
import { CommuterController } from './commuter.controller';
import { CommuterService } from './commuter.service';

@Module({
  controllers: [CommuterController],
  providers: [CommuterService]
})
export class CommuterModule {}
