import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { AuthenticationGuard } from './auth/guards/auth.guard';

@UseGuards(AuthenticationGuard)
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) { }

  @Get()
  getHello(@Req() req) {
    return { message: 'Accessed Resource', userId: req.userId };
  }
}
