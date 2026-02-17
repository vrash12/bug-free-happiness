import { Module } from '@nestjs/common';
import { PaoController } from './pao.controller';
import { PaoService } from './pao.service';

@Module({
  controllers: [PaoController],
  providers: [PaoService]
})
export class PaoModule {}
