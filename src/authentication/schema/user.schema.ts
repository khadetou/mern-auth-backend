import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
// import { now } from 'mongoose';

export type UserDocument = User & Document;

@Schema({ timestamps: true, collection: 'users' })
export class User {
  @Prop({ required: true, type: String })
  name: string;

  @Prop({ type: String, required: true, unique: true })
  email: string;

  @Prop({ required: false, type: String, default: 'Google Sign In' })
  password: string;

  //   @Prop({ default: now() })
  //   createdAt: Date;

  //   @Prop({ default: now() })
  //   updatedAt: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);
