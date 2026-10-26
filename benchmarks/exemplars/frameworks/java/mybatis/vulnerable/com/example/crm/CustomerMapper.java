package com.example.crm;

import java.util.List;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

@Mapper
public interface CustomerMapper {

    @Select("SELECT * FROM customer WHERE id = #{id}")
    Customer byId(@Param("id") long id);

    @Select("SELECT * FROM customer WHERE name LIKE '%${term}%'")   // frame-expect: CWE-89
    List<Customer> search(@Param("term") String term);

    @Select("SELECT * FROM customer ORDER BY ${column} ${direction}")   // frame-expect: CWE-89
    List<Customer> sorted(@Param("column") String column, @Param("direction") String direction);

    @Update("UPDATE customer SET note = #{note} WHERE id = #{id}")
    int annotate(@Param("id") long id, @Param("note") String note);

    @Delete("DELETE FROM customer WHERE region = '${region}'")   // frame-expect: CWE-89
    int purgeRegion(@Param("region") String region);
}
