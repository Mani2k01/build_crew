require('dotenv').config();
const mysql = require("mysql2/promise");

class Database{
    constructor(databasename){
        this.databasename = databasename;
        console.log("selected database : ", this.databasename);
        this.pool = mysql.createPool({
            uri: process.env.DATABASE_URL
        });
        // this.pool = mysql.createPool({
        //     user: "root",
        //     host: "localhost",
        //     database: this.databasename,
        //     password: "Manikandan12",
        //     port: 3306,
        // });
        console.log(`Connected to database: ${this.databasename}`);
    }

    async getconnection(){
        try{
            const connection = await this.pool.getConnection();
            return connection;
        }catch(err){
            throw err;
        }
    }

    async insert_data(query, values){
        const connection = await this.getconnection();
        try{
            await connection.execute(query, values);
            console.log('Data inserted successfully');
            return true;
        }catch(err){
            console.log('Error inserting data:', err);
            return false;
        }finally{
            connection.release();
        }
    }

  async update_data(updateQuery, data) {
    const conn = await this.getconnection();
    try {
      await conn.execute(updateQuery, data);
      console.log("Data updated successfully.");
      return true;
    } catch (err) {
      console.error("Error:", err);
      return false;
    } finally {
      conn.release();
    }
  }

    async fetch_data(query, values){
        const conn = await this.getconnection();
        try{
            const [rows] = await conn.execute(query, values);
            // console.log("Fetched Rows: ", rows);
            return rows.length > 0 ? rows[0] : null;
        }catch(err){
            console.log("Error : ", err);
            return null;
        }finally{
            conn.release();
        }

    }

    async fetch_all_data(query, values){
        const conn = await this.getconnection();
        try{
            const [rows] = await conn.execute(query, values);
            return rows;
        }catch(err){
            console.log("Error : ", err);
            return null;
        }finally{
            conn.release();
        }
    }

    async fetch_data_without_value(query){
        const conn = await this.getconnection();
        try{
            const [rows] = await conn.execute(query);
            // console.log("Fetched Rows: ", rows);
            return rows;
        }catch(err){
            console.log("error : ", err);
            return null;
        }finally{
            conn.release();
        }
    }

}

module.exports = Database