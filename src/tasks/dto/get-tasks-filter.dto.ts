import { TaskStatus } from "../task-status.enum";
import { IsOptional, IsIn, IsNotEmpty } from "class-validator";

export class GetTasksFilterDto {
    @IsOptional()
    @IsIn([TaskStatus.IN_PROGRESS, TaskStatus.DONE, TaskStatus.OPEN])
    status: TaskStatus;

    @IsOptional()
    @IsNotEmpty()
    search: string;
}