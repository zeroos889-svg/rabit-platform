/**
 * JWT Token Management
 * Handles creation and verification of JWT tokens
 */

import * as jose from "jose";
import { ENV } from "./env";

export interface SessionPayload {
  userId: number;
  email: string;
  role: string;
}

/**
 * Create a session token
 */
export function createSessionToken(payload: SessionPayload): string {
  const secret = new TextEncoder().encode(ENV.jwtSecret);
  
  return new jose.SignJWT({
    userId: payload.userId,
    email: payload.email,
    role: payload.role,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(secret);
}

/**
 * Verify a session token
 */
export function verifySessionToken(token: string): SessionPayload | null {
  try {
    const secret = new TextEncoder().encode(ENV.jwtSecret);
    const { payload } = jose.jwtVerify(token, secret);
    
    return {
      userId: payload.userId as number,
      email: payload.email as string,
      role: payload.role as string,
    };
  } catch (error) {
    console.error("[JWT] Token verification failed", error);
    return null;
  }
}
