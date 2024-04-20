import { ObjectType } from "@nestjs/graphql";
import { BaseEntity } from "../base.entity/base.entity";
import { Profile } from "@prisma/client";

@ObjectType()
export class ProfileEntity extends BaseEntity implements Profile {
    password: string;
}
