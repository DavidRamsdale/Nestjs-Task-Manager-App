import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserRepository } from './user.repository';
import { InjectRepository } from '@nestjs/typeorm';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './jwt-payload.interface';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(UserRepository)
        private userRepository: UserRepository,
        private jswService: JwtService
    ) { }

    async signUp(authCredtialsDto: AuthCredentialsDto): Promise<void> {
        return this.userRepository.signUp(authCredtialsDto);
    }

    async signIn(AuthCredentialsDto: AuthCredentialsDto): Promise<{ accessToken: string }> {
        const username = await this.userRepository.validateUserPassword(AuthCredentialsDto)

        if (!username) {
            throw new UnauthorizedException('Invalid Credentials')
        }

        const payload: JwtPayload = { username };
        const accessToken = await this.jswService.sign(payload);

        return { accessToken };
    }
}
