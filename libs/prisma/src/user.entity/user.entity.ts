import { Field, Int, ObjectType } from "@nestjs/graphql";
import { BaseEntity } from "../base.entity/base.entity";
import { User } from "@prisma/client";
import { ProfileEntity } from "../profile.entity/profile.entity";

@ObjectType()
export class UserEntity extends BaseEntity implements User {
    @Field()
    hash_key: string;

    @Field()
    account: string;

    @Field(() => Int)
    role: number;

    @Field(() => Int)
    profileId: number;

    @Field(() => ProfileEntity, { nullable: true })
    profile: ProfileEntity

    @Field()
    name: string;

    @Field({ nullable: true })
    token?: string
}
