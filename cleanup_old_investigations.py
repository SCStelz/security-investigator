"""
Cleanup Old Investigation Files
Removes investigation JSON and HTML report files older than specified retention period for data privacy
"""

import os
import time
from datetime import datetime, timedelta
import argparse


def cleanup_old_investigations(temp_dir: str = "temp", reports_dir: str = "reports", retention_days: int = 30, dry_run: bool = False):
    """
    Remove investigation JSON and HTML files older than retention period
    
    Args:
        temp_dir: Directory containing investigation JSON files (default: temp/)
        reports_dir: Directory containing HTML reports (default: reports/)
        retention_days: Number of days to retain files (default: 30)
        dry_run: If True, only show what would be deleted without actually deleting
    
    Returns:
        Tuple of (files_deleted, space_freed_bytes)
    """
    cutoff_time = time.time() - (retention_days * 86400)  # Convert days to seconds
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    
    files_deleted = 0
    space_freed = 0
    
    print(f"🔍 Scanning for old investigation files...")
    print(f"📅 Retention policy: {retention_days} days (delete files older than {cutoff_date.strftime('%Y-%m-%d')})")
    print()
    
    # Process JSON files in temp/
    if os.path.exists(temp_dir):
        print(f"📂 Checking {temp_dir}/ for JSON files...")
        for filename in os.listdir(temp_dir):
            # Only process investigation JSON files
            if not filename.startswith("investigation_") or not filename.endswith(".json"):
                continue
            
            # Skip SCRUBBED files - these are sanitized for GitHub commits
            if "SCRUBBED" in filename:
                continue
            
            filepath = os.path.join(temp_dir, filename)
            
            # Get file modification time
            try:
                file_mtime = os.path.getmtime(filepath)
                file_size = os.path.getsize(filepath)
                file_date = datetime.fromtimestamp(file_mtime)
                
                if file_mtime < cutoff_time:
                    age_days = (datetime.now() - file_date).days
                    
                    if dry_run:
                        print(f"  [DRY RUN] Would delete: {filename}")
                        print(f"            Age: {age_days} days | Size: {file_size:,} bytes | Last modified: {file_date.strftime('%Y-%m-%d %H:%M:%S')}")
                    else:
                        os.remove(filepath)
                        print(f"  ✓ Deleted: {filename}")
                        print(f"    Age: {age_days} days | Size: {file_size:,} bytes")
                    
                    files_deleted += 1
                    space_freed += file_size
            
            except OSError as e:
                print(f"  ⚠️ Error processing {filename}: {e}")
            except PermissionError as e:
                print(f"  ⚠️ Permission denied for {filename}: {e}")

    # Process HTML report files in reports/user-investigations/
    user_inv_dir = os.path.join(reports_dir, "user-investigations")
    if os.path.exists(user_inv_dir):
        print(f"\n📂 Checking {user_inv_dir}/ for HTML reports...")
        for filename in os.listdir(user_inv_dir):
            # Only process investigation report HTML files
            if not filename.startswith("Investigation_Report_") or not filename.endswith(".html"):
                continue
            
            # Skip SCRUBBED files - these are sanitized for GitHub commits
            if "SCRUBBED" in filename:
                continue
            
            filepath = os.path.join(user_inv_dir, filename)
            
            # Get file modification time
            try:
                file_mtime = os.path.getmtime(filepath)
                file_size = os.path.getsize(filepath)
                file_date = datetime.fromtimestamp(file_mtime)
                
                if file_mtime < cutoff_time:
                    age_days = (datetime.now() - file_date).days
                    
                    if dry_run:
                        print(f"  [DRY RUN] Would delete: {filename}")
                        print(f"            Age: {age_days} days | Size: {file_size:,} bytes | Last modified: {file_date.strftime('%Y-%m-%d %H:%M:%S')}")
                    else:
                        os.remove(filepath)
                        print(f"  ✓ Deleted: {filename}")
                        print(f"    Age: {age_days} days | Size: {file_size:,} bytes")
                    
                    files_deleted += 1
                    space_freed += file_size
            
            except OSError as e:
                print(f"  ⚠️ Error processing {filename}: {e}")
            except PermissionError as e:
                print(f"  ⚠️ Permission denied for {filename}: {e}")

    print()
    if files_deleted > 0:
        space_freed_mb = space_freed / (1024 * 1024)
        if dry_run:
            print(f"📊 Dry run summary: {files_deleted} file(s) would be deleted, freeing {space_freed_mb:.2f} MB")
        else:
            print(f"✅ Cleanup complete: {files_deleted} file(s) deleted, freed {space_freed_mb:.2f} MB")
    else:
        print(f"✅ No files to delete (all files within {retention_days}-day retention period)")
    
    return files_deleted, space_freed


def main():
    parser = argparse.ArgumentParser(
        description="Cleanup old investigation JSON and HTML report files for data privacy compliance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Preview what would be deleted (dry run)
  python cleanup_old_investigations.py --dry-run

  # Delete files older than 30 days (default)
  python cleanup_old_investigations.py

  # Delete files older than 7 days
  python cleanup_old_investigations.py --days 7

  # Delete files older than 90 days from custom directories
  python cleanup_old_investigations.py --days 90 --temp-dir data/ --reports-dir my_reports/
        """
    )
    
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Retention period in days (default: 30)"
    )
    
    parser.add_argument(
        "--temp-dir",
        type=str,
        default="temp",
        help="Directory containing investigation JSON files (default: temp/)"
    )
    
    parser.add_argument(
        "--reports-dir",
        type=str,
        default="reports",
        help="Directory containing HTML report files (default: reports/)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be deleted without actually deleting"
    )
    
    args = parser.parse_args()
    
    # Validate retention days
    if args.days < 1:
        print("❌ Error: Retention period must be at least 1 day")
        return
    
    cleanup_old_investigations(
        temp_dir=args.temp_dir,
        reports_dir=args.reports_dir,
        retention_days=args.days,
        dry_run=args.dry_run
    )


if __name__ == "__main__":
    main()
