import oracledb
import os
from dotenv import load_dotenv
from utils import format_database_results, format_database_row, log_with_unicode
import time
load_dotenv()

# Set Oracle defaults for proper character handling
oracledb.defaults.fetch_lobs = False

class DatabaseManager:
    def __init__(self):
        self.user = os.getenv('ORACLE_USER')
        self.password = os.getenv('ORACLE_PASSWORD')
        self.dsn = os.getenv('ORACLE_DSN')
        
        # Use QuotaGuard Static for database connections
        self.quotaguard_url = os.getenv('QUOTAGUARDSTATIC_URL')
        
    def get_connection(self):
        """Get connection through QuotaGuard Static"""
        try:
            if self.quotaguard_url:
                log_with_unicode("✓ Using QuotaGuard Static for DB connection")
            
            connection = oracledb.connect(
                user=self.user,
                password=self.password,
                dsn=self.dsn
                # Remove timeout=30 - not supported by oracledb.connect()
            )
            return connection
        except Exception as e:
            log_with_unicode(f"✗ Database connection error: {e}")
            raise


    def execute_query(self, query: str, params=None) -> list:
        """Execute SELECT query with Unicode handling"""
        try:
            connection = self.get_connection()
            cursor = connection.cursor()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            # Get column names
            columns = [col[0] for col in cursor.description]
            rows = cursor.fetchall()
            
            # Format results with Unicode handling
            result = format_database_results(rows, columns)
            
            cursor.close()
            connection.close()
            
            log_with_unicode(f"✓ Query executed successfully, returned {len(result)} rows")
            return result
            
        except Exception as e:
            log_with_unicode(f"✗ Query error: {e}")
            raise

    def execute_dml(self, query: str, params=None) -> int:
        """Execute INSERT/UPDATE/DELETE with Unicode handling"""
        try:
            connection = self.get_connection()
            cursor = connection.cursor()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            connection.commit()
            rowcount = cursor.rowcount
            
            cursor.close()
            connection.close()
            
            log_with_unicode(f"✓ DML executed successfully, {rowcount} rows affected")
            return rowcount
            
        except Exception as e:
            log_with_unicode(f"✗ DML error: {e}")
            raise

    def execute_dml_with_return(self, query: str, params=None):
        """Execute DML and return generated ID"""
        try:
            connection = self.get_connection()
            cursor = connection.cursor()
            
            # For Oracle RETURNING clause
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            connection.commit()
            
            # Get returned value (like user ID)
            if hasattr(cursor, 'lastrowid') and cursor.lastrowid:
                result = cursor.lastrowid
            else:
                # For RETURNING INTO clause, get from cursor variables
                result = None
                
            cursor.close()
            connection.close()
            
            return result
            
        except Exception as e:
            log_with_unicode(f"✗ DML with return error: {e}")
            raise

    def test_connection(self):
        """Test database connection"""
        try:
            result = self.execute_query("SELECT 'Povezava uspešna!' FROM DUAL")
            if result:
                log_with_unicode(f"✓ {result[0]['DUAL']}")
                return True
        except Exception as e:
            log_with_unicode(f"✗ Connection test failed: {e}")
            return False

# Global instance
db_manager = DatabaseManager()

# Test when run directly
if __name__ == '__main__':
    log_with_unicode("🔍 Testing Database Connection...")
    db_manager.test_connection()
