import sqlite3

class Base:
    def __init__(self, name: str = "base.db") -> None:
        self.name = name
        self.conn: sqlite3.Connection | None = None
        self.cur: sqlite3.Cursor | None = None

    def __enter__(self) -> "Base":
        self.conn = sqlite3.connect(self.name)
        self.conn.row_factory = sqlite3.Row
        self.cur = self.conn.cursor()
        return self

    def create_table(self) -> None:
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS USERS (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                LOGIN TEXT NOT NULL UNIQUE,
                PASS TEXT NOT NULL,
                CREATE_AT DATETIME,
                UPDATE_AT DATETIME,
                DELETE_AT DATETIME,
                ACTIVE BOOLEAN NOT NULL
            )
        """)
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS CERTIFICATES (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                CERTIFICATE_NAME TEXT NOT NULL,
                EXPIRATION_TIME DATETIME,
                DATE_CHANGE DATETIME,
                RECALLED BOOLEAN NOT NULL
            )
        """)


    def select_table(self,LOGIN:str) -> list:
        self.cur.execute("SELECT LOGIN, PASS, ACTIVE FROM USERS WHERE LOGIN=?",(LOGIN,))
        return self.cur.fetchone()


    def insert_data(
        self,
        login: str,
        password: str,
        create_at: str,
        active: bool,
    ) -> None:
        self.cur.execute(
            "INSERT INTO USERS (LOGIN, PASS, CREATE_AT, ACTIVE) VALUES (?, ?, ?, ?)",
            (login, password, create_at, active),
        )

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if self.conn:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            self.conn.close()
        return False

    