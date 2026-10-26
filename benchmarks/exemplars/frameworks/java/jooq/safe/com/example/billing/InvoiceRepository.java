package com.example.billing;

import java.util.List;
import org.jooq.Condition;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.jooq.Result;
import org.jooq.impl.DSL;

public class InvoiceRepository {

    private final DSLContext dsl;

    public InvoiceRepository(DSLContext dsl) {
        this.dsl = dsl;
    }

    public Result<Record> byCustomer(String customer) {
        return dsl.fetch("SELECT * FROM invoice WHERE customer = ?", customer);
    }

    public Result<Record> byStatus(String status, String sort) {
        return dsl.resultQuery("SELECT * FROM invoice WHERE status = ? ORDER BY " + ("amount".equals(sort) ? "amount" : "created"), status).fetch();
    }

    public List<Record> search(String where) {
        Condition extra = DSL.condition("customer = ?", where);
        return dsl.select().from(DSL.table("invoice")).where(extra).fetch();
    }

    public Result<Record> sorted(String column) {
        return dsl.select().from(DSL.table("invoice")).orderBy(DSL.field(DSL.name(column))).fetch();
    }

    public int close(String invoiceId) {
        return dsl.execute("UPDATE invoice SET closed = true WHERE id = ?", Long.parseLong(invoiceId));
    }
}
