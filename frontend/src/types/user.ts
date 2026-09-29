export interface StudentBrief {
  sno: string;
  name?: string | null;
  email?: string | null;
}

export interface TeacherBrief {
  id: number;
  name?: string | null;
  email?: string | null;
  title?: string | null;
  image?: string | null;
}

export interface UserBrief {
  id: number;
  username: string;
  avatar?: string | null;
  identity?: string | null;
}

export interface UserResponse {
  id: number;
  username: string;
  email: string;
  identity?: string | null;
  role: string;
  avatar: string;
  confirmed: boolean;
  register_time?: string | null;
  unread_notification_count: number;
  student?: StudentBrief | null;
  teacher?: TeacherBrief | null;
}

export interface UserProfile extends Omit<UserResponse, 'email'> {
  email?: string | null;
  homepage?: string | null;
  description?: string | null;
  gender?: string | null;
  /** is_following_hidden 且非本人查看时为 null（后端隐藏统计） */
  following_count: number | null;
  follower_count: number | null;
  access_count: number;
  is_following_hidden: boolean;
  is_profile_hidden: boolean;
  /** 当前登录用户是否已关注该用户 */
  is_following: boolean;
}

export interface UserUpdate {
  username?: string;
  avatar?: string | null;
  homepage?: string | null;
  description?: string | null;
  gender?: string | null;
  is_following_hidden?: boolean;
  is_profile_hidden?: boolean;
}

export interface BindStudentRequest {
  sno: string;
}

export interface NotificationResponse {
  id: number;
  from_user_id?: number | null;
  operation: string;
  ref_class?: string | null;
  ref_obj_id?: number | null;
  ref_display_class?: string | null;
  display_text?: string | null;
  time?: string | null;
}
