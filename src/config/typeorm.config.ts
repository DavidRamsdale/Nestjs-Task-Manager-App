import { TypeOrmModuleOptions } from '@nestjs/typeorm'

export const typeOrmConfig: TypeOrmModuleOptions = {
    type: 'postgres',
    host: 'localhost',
    port: 5432,
    username: process.env.username,
    password: process.env.password,
    database: 'taskmangement',
    entities: [__dirname + '/../**/*.entity.{js,ts}'],
    synchronize: true,
}