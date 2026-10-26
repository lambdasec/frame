package com.app.dao;

import java.sql.ResultSet;

public class OrderDao extends BaseDao {
    public ResultSet byCustomer(String customer) throws Exception {
        return run("SELECT * FROM orders WHERE customer = '" + customer + "'");
    }
}
