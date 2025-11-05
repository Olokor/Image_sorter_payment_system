"""
Diagnostic and Cleanup Script for Photo Sorter MongoDB
Run this to check and clean up problematic user accounts
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

MONGO_DB_URL = os.getenv("MONGO_DB_URL", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "photosorter_db")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def truncate_password(password: str) -> str:
    """Truncate password to 72 bytes for bcrypt compatibility"""
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        return password_bytes[:72].decode('utf-8', errors='ignore')
    return password


def hash_password(password: str) -> str:
    """Hash password with bcrypt (max 72 bytes)"""
    truncated = truncate_password(password)
    return pwd_context.hash(truncated)


async def main():
    print("\n" + "="*70)
    print("PHOTO SORTER - MongoDB Diagnostic & Cleanup")
    print("="*70 + "\n")
    
    # Connect to MongoDB
    client = AsyncIOMotorClient(MONGO_DB_URL)
    db = client[MONGO_DB_NAME]
    
    print(f"📊 Connected to: {MONGO_DB_URL}")
    print(f"🗄️  Database: {MONGO_DB_NAME}\n")
    
    # Check users collection
    users_collection = db["users"]
    
    try:
        users_count = await users_collection.count_documents({})
        print(f"👥 Total users in database: {users_count}\n")
        
        if users_count == 0:
            print("✓ No users found. Database is clean.")
            print("  You can now signup with a new account.\n")
            return
        
        # List all users
        print("📋 Existing users:")
        print("-" * 70)
        
        users = []
        async for user in users_collection.find({}):
            users.append(user)
            email = user.get('email', 'N/A')
            name = user.get('name', 'N/A')
            verified = user.get('email_verified', False)
            created = user.get('created_at', 'N/A')
            
            print(f"  Email: {email}")
            print(f"  Name: {name}")
            print(f"  Verified: {'✓' if verified else '✗'}")
            print(f"  Created: {created}")
            print(f"  Password Hash Length: {len(user.get('password_hash', ''))}")
            print("-" * 70)
        
        # Ask user what to do
        print("\n⚠️  OPTIONS:")
        print("  1. Delete ALL users (clean slate)")
        print("  2. Delete specific user by email")
        print("  3. Re-hash all user passwords (fix bcrypt issue)")
        print("  4. Exit without changes")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == "1":
            confirm = input("\n⚠️  Are you SURE you want to delete ALL users? (yes/no): ").strip().lower()
            if confirm == "yes":
                result = await users_collection.delete_many({})
                print(f"\n✓ Deleted {result.deleted_count} user(s)")
                
                # Also clean up OTP verifications and licenses
                await db["otp_verifications"].delete_many({})
                await db["licenses"].delete_many({})
                print("✓ Cleaned up related data (OTP, licenses)")
            else:
                print("\n✗ Cancelled")
        
        elif choice == "2":
            email = input("\nEnter email to delete: ").strip()
            result = await users_collection.delete_one({"email": email})
            if result.deleted_count > 0:
                print(f"\n✓ Deleted user: {email}")
                
                # Clean up related data
                await db["otp_verifications"].delete_many({"email": email})
                print("✓ Cleaned up related OTP data")
            else:
                print(f"\n✗ User not found: {email}")
        
        elif choice == "3":
            print("\n🔄 Re-hashing passwords...")
            print("⚠️  NOTE: You'll need to know the original passwords or reset them\n")
            
            for user in users:
                email = user.get('email')
                print(f"\nUser: {email}")
                print("  Options:")
                print("  1. Enter original password to re-hash")
                print("  2. Set new password")
                print("  3. Skip this user")
                
                option = input("  Choice (1-3): ").strip()
                
                if option == "1":
                    password = input("  Enter original password: ").strip()
                    new_hash = hash_password(password)
                    await users_collection.update_one(
                        {"_id": user["_id"]},
                        {"$set": {"password_hash": new_hash}}
                    )
                    print("  ✓ Password re-hashed")
                
                elif option == "2":
                    password = input("  Enter new password: ").strip()
                    if len(password) < 6:
                        print("  ✗ Password too short (min 6 chars)")
                        continue
                    new_hash = hash_password(password)
                    await users_collection.update_one(
                        {"_id": user["_id"]},
                        {"$set": {"password_hash": new_hash}}
                    )
                    print("  ✓ New password set")
                
                else:
                    print("  → Skipped")
        
        else:
            print("\n✗ No changes made")
        
        print("\n" + "="*70)
        print("✓ Diagnostic complete")
        print("="*70 + "\n")
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
    
    finally:
        client.close()


if __name__ == "__main__":
    asyncio.run(main())