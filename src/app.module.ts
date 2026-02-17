import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './modules/auth/auth.module';
import { CommuterModule } from './modules/commuter/commuter.module';
import { PaoModule } from './modules/pao/pao.module';
import { TellerModule } from './modules/teller/teller.module';
import { ManagerModule } from './modules/manager/manager.module';

@Module({
  imports: [AuthModule, CommuterModule, PaoModule, TellerModule, ManagerModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
