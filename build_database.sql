DROP DATABASE IF EXISTS epsilon;
CREATE DATABASE epsilon;

\c epsilon

CREATE TABLE tbl_cve (
    cve_id                      VARCHAR(32) PRIMARY KEY,
    description                 TEXT NOT NULL,
    cvss                        REAL NOT NULL,
    published_date              TIMESTAMP NOT NULL,
    reference_links             TEXT,
    exploitability_score        REAL,
    impact_score                REAL,
    severity                    VARCHAR(16),
    cvss_access_vector          VARCHAR(16),
    cvss_vector_string          VARCHAR(64),
    cvss_access_complexity      VARCHAR(16),
    cvss_authentication         VARCHAR(16),
    cvss_confidentiality_impact VARCHAR(16),
    cvss_integrity_impact       VARCHAR(16),
    cvss_availability_impact    VARCHAR(16),
    last_modified_date          TIMESTAMP
);

CREATE TABLE tbl_cwe (
    cwe_id      VARCHAR(16) PRIMARY KEY,
    name        VARCHAR(256) NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE xref_cve_cwe (
    id                  SERIAL PRIMARY KEY,
    id_cve              VARCHAR(32),
    id_cwe              VARCHAR(16),
    FOREIGN KEY(id_cve) REFERENCES tbl_cve(cve_id),
    FOREIGN KEY(id_cwe) REFERENCES tbl_cwe(cwe_id)
);

CREATE TABLE tbl_capec (
    capec_id      VARCHAR(32) PRIMARY KEY,
    name          VARCHAR(256) NOT NULL,
    description   TEXT NOT NULL,
    prerequisites TEXT NOT NULL,
    mitigations   TEXT NOT NULL
);

CREATE TABLE xref_cwe_capec (
    id                    SERIAL PRIMARY KEY,
    id_cwe                VARCHAR(16),
    id_capec              VARCHAR(32),
    FOREIGN KEY(id_cwe)   REFERENCES tbl_cwe(cwe_id),
    FOREIGN KEY(id_capec) REFERENCES tbl_capec(capec_id)
);

CREATE TABLE tbl_user (
    user_id SERIAL PRIMARY KEY,
    email VARCHAR(320) UNIQUE NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE tbl_vendor (
    vendor_id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE tbl_product (
    product_id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    id_vendor INT,
    FOREIGN KEY(id_vendor) REFERENCES tbl_vendor(vendor_id)
);

CREATE TABLE xref_cve_product (
    id SERIAL PRIMARY KEY,
    id_cve VARCHAR(32),
    id_product INT,
    FOREIGN KEY(id_cve) REFERENCES tbl_cve(cve_id),
    FOREIGN KEY(id_product) REFERENCES tbl_product(product_id)
);

CREATE TABLE tbl_subscription (
    subscription_id SERIAL PRIMARY KEY,
    custom_regex TEXT,
    cvss REAL,
    created_at TIMESTAMP NOT NULL,
    confirmed BOOLEAN NOT NULL,
    id_user INT,
    id_product INT NULL,
    id_vendor INT,
    UNIQUE (id_product, id_vendor, id_user),
    FOREIGN KEY(id_user) REFERENCES tbl_user(user_id),
    FOREIGN KEY(id_product) REFERENCES tbl_product(product_id),
    FOREIGN KEY(id_vendor) REFERENCES tbl_vendor(vendor_id)
);

CREATE TABLE tbl_cve_top_ten (
    id SERIAL PRIMARY KEY,
    id_cve VARCHAR(32),
    FOREIGN KEY(id_cve) REFERENCES tbl_cve(cve_id)
);

CREATE TABLE tbl_vendor_top_ten (
    id SERIAL PRIMARY KEY,
    id_vendor INT NOT NULL,
    vulns INT NOT NULL,
    FOREIGN KEY(id_vendor) REFERENCES tbl_vendor(vendor_id)
);

CREATE TABLE tbl_operating_system (
    operating_system_id SERIAL PRIMARY KEY,
    name TEXT,
    id_product INT,
    os_type TEXT,
    UNIQUE (name, id_product),
    FOREIGN KEY(id_product) REFERENCES tbl_product(product_id)
);

CREATE INDEX idx_cve_id ON tbl_cve(cve_id);

CREATE OR REPLACE FUNCTION get_cve("id_cve" VARCHAR(32))
RETURNS SETOF tbl_cve LANGUAGE SQL
AS $$
    SELECT * FROM tbl_cve
    WHERE cve_id="id_cve"
    LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION get_cve_by_description("keyword" TEXT)
RETURNS SETOF tbl_cve LANGUAGE SQL
AS $$
    SELECT * FROM tbl_cve
    WHERE description ILIKE '%'||"keyword"||'%'
    ORDER BY cve_id DESC;
$$;

CREATE OR REPLACE FUNCTION get_cve_count()
RETURNS bigint LANGUAGE SQL
AS $$
    SELECT COUNT(*) FROM tbl_cve;
$$;

CREATE OR REPLACE FUNCTION get_cve_in_range("skip" INT, "count" INT)
RETURNS SETOF tbl_cve LANGUAGE SQL
AS $$
    SELECT * FROM tbl_cve
    ORDER BY
        last_modified_date DESC,
        published_date DESC,
        cve_id DESC
    LIMIT "count" OFFSET "skip";
$$;

CREATE OR REPLACE FUNCTION get_cve_by_cvss("_cvss" REAL)
RETURNS SETOF tbl_cve LANGUAGE SQL
AS $$
    SELECT * FROM tbl_cve
    WHERE cvss="_cvss";
$$;

CREATE OR REPLACE FUNCTION get_cve_by_vendor("vendor_name" TEXT)
RETURNS SETOF tbl_cve LANGUAGE SQL
AS $$
    SELECT c.* FROM tbl_cve AS c
    LEFT JOIN xref_cve_product AS xf ON xf.id_cve=c.cve_id
    LEFT JOIN tbl_product AS p ON p.product_id=id_product
    LEFT JOIN tbl_vendor as v ON v.vendor_id=p.id_vendor
    WHERE v.name="vendor_name";
$$;

CREATE OR REPLACE FUNCTION get_cve_by_product("product_id" INT)
RETURNS SETOF tbl_cve LANGUAGE SQL
AS $$
    SELECT c.* FROM tbl_cve AS c
    LEFT JOIN xref_cve_product AS xf ON xf.id_cve=c.cve_id
    WHERE xf.id_product="product_id";
$$;

CREATE OR REPLACE FUNCTION get_cve_by_date("start" TIMESTAMP DEFAULT NULL, "end" TIMESTAMP DEFAULT NULL)
RETURNS SETOF tbl_cve LANGUAGE plpgsql
AS $$
    BEGIN
        IF "start" IS NOT NULL AND "end" IS NOT NULL THEN
            RETURN QUERY
            SELECT * FROM tbl_cve
            WHERE last_modified_date BETWEEN "start" AND "end";
        ELSIF "start" THEN
            RETURN QUERY
            SELECT * FROM tbl_cve
            WHERE last_modified_date > "start";
        ELSIF "end" THEN
            RETURN QUERY
            SELECT * FROM tbl_cve
            WHERE last_modified_date < "end";
        ELSE
            RETURN QUERY
            SELECT NULL;
        END IF;
    END;
$$;

CREATE OR REPLACE FUNCTION get_cve_by_os("os_name" TEXT)
RETURNS SETOF tbl_cve LANGUAGE SQL
AS $$
    SELECT c.* FROM tbl_cve as c
    LEFT JOIN xref_cve_product AS xf ON xf.id_cve=c.cve_id
    LEFT JOIN tbl_operating_system AS os ON os.id_product=xf.id_product
    WHERE os.name="os_name";
$$;

CREATE OR REPLACE FUNCTION get_top_ten_cve()
RETURNS SETOF tbl_cve LANGUAGE SQL
AS $$
    SELECT * FROM tbl_cve
    WHERE EXISTS (
        SELECT FROM tbl_cve_top_ten
        WHERE cve_id=id_cve
    );
$$;

CREATE OR REPLACE FUNCTION get_top_ten_vendor()
RETURNS TABLE("name" TEXT, "vulns" INT) LANGUAGE SQL
AS $$
    SELECT v.name, vulns FROM tbl_vendor_top_ten
    LEFT JOIN tbl_vendor as v ON v.vendor_id=id_vendor
    ORDER BY vulns DESC, name DESC;
$$;

CREATE OR REPLACE FUNCTION get_top_ten_vendor_weekly()
 RETURNS TABLE("name" TEXT, vulns BIGINT) LANGUAGE SQL
 AS $$
     SELECT v.name, COUNT(DISTINCT c.cve_id) AS "vulns" FROM tbl_cve AS c
     LEFT JOIN xref_cve_product AS xf ON xf.id_cve=c.cve_id
     LEFT JOIN tbl_product AS p ON p.product_id=id_product
     LEFT JOIN tbl_vendor as v ON v.vendor_id=p.id_vendor
     WHERE c.published_date >= CURRENT_DATE - interval '7 days' AND v.name IS NOT NULL                                                                                                                                                               GROUP BY v.name
     ORDER BY "vulns" DESC, v.name DESC
     LIMIT 10;
 $$;

CREATE OR REPLACE FUNCTION get_all_cwe()
RETURNS SETOF tbl_cwe LANGUAGE SQL
AS $$
    SELECT * FROM tbl_cwe;
$$;

CREATE OR REPLACE FUNCTION get_capec_for_cwe("cwe_id" VARCHAR(16))
RETURNS SETOF tbl_capec LANGUAGE SQL
AS $$
    SELECT c.* FROM tbl_capec as c
    LEFT JOIN xref_cwe_capec AS xf ON xf.id_capec=c.capec_id
    WHERE xf.id_cwe="cwe_id";
$$;

CREATE OR REPLACE FUNCTION get_user_daily_cves("id_subscription" INT)
RETURNS SETOF tbl_cve LANGUAGE SQL
AS $$
    SELECT c.* FROM tbl_cve AS c
    LEFT JOIN xref_cve_product AS xf ON xf.id_cve=c.cve_id
    LEFT JOIN tbl_product AS p ON xf.id_product=p.product_id
    LEFT JOIN tbl_subscription AS s ON s.subscription_id="id_subscription"
    WHERE s.confirmed IS True AND c.cvss >= s.cvss AND  
    ((s.id_product=p.product_id OR
      s.id_vendor=p.id_vendor) AND
      c.description ~* s.custom_regex)
    AND c.last_modified_date > CURRENT_TIMESTAMP - interval '1 day'
    GROUP BY c.cve_id;
$$;

CREATE OR REPLACE FUNCTION get_user_subscriptions("user_id" INT)
RETURNS SETOF tbl_subscription LANGUAGE SQL
AS $$
    SELECT * FROM tbl_subscription
    WHERE id_user="user_id" AND confirmed=TRUE;
$$;

CREATE OR REPLACE FUNCTION get_subscription_by_id("id" INT)
RETURNS SETOF tbl_subscription LANGUAGE SQL
AS $$
    SELECT * FROM tbl_subscription
    WHERE subscription_id="id";
$$;

CREATE OR REPLACE FUNCTION get_capec("id_capec" VARCHAR(32))
RETURNS SETOF tbl_capec LANGUAGE SQL
AS $$
    SELECT * FROM tbl_capec
    WHERE capec_id="id_capec";
$$;

CREATE OR REPLACE FUNCTION get_cwe("id_cwe" VARCHAR(16))
RETURNS SETOF tbl_cwe LANGUAGE SQL
AS $$
    SELECT * FROM tbl_cwe
    WHERE cwe_id="id_cwe"
    LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION get_cwe_by_description("keyword" TEXT)
RETURNS SETOF tbl_cwe LANGUAGE SQL
AS $$
    SELECT * FROM tbl_cwe as c
    WHERE c.name ILIKE '%'||"keyword"||'%' OR c.description ILIKE '%'||"keyword"||'%'
    ORDER BY c.cwe_id DESC;
$$;

CREATE OR REPLACE FUNCTION get_vendor("vendor_name" TEXT)
RETURNS SETOF tbl_vendor LANGUAGE SQL
AS $$
    SELECT * FROM tbl_vendor
    WHERE name="vendor_name";
$$;

CREATE OR REPLACE FUNCTION get_vendor_by_id("id" INT)
RETURNS SETOF tbl_vendor LANGUAGE SQL
AS $$
    SELECT * FROM tbl_vendor
    WHERE vendor_id="id";
$$;

CREATE OR REPLACE FUNCTION get_vendor_cwe_count("vendor_name" TEXT, "last_week" BOOLEAN)
RETURNS bigint LANGUAGE plpgsql
AS $$
    BEGIN
        IF "last_week" IS FALSE THEN
            RETURN (
                SELECT COUNT(*) FROM tbl_cve AS c
                LEFT JOIN xref_cve_product AS xf ON xf.id_cve=c.cve_id
                LEFT JOIN tbl_product AS p ON p.product_id=id_product
                LEFT JOIN tbl_vendor as v ON v.vendor_id=p.id_vendor
                WHERE v.name="vendor_name"
            );
        ELSE
            RETURN (
                SELECT COUNT(*) FROM tbl_cve AS c
                LEFT JOIN xref_cve_product AS xf ON xf.id_cve=c.cve_id
                LEFT JOIN tbl_product AS p ON p.product_id=id_product
                LEFT JOIN tbl_vendor as v ON v.vendor_id=p.id_vendor
                WHERE v.name="vendor_name" AND 
                    (c.last_modified_date >= date_trunc('week', CURRENT_TIMESTAMP - interval '1 week') AND
                    c.last_modified_date <= date_trunc('week', CURRENT_TIMESTAMP))
            );
        END IF;
    END;
$$;

CREATE OR REPLACE FUNCTION get_vendors("vendor_name" TEXT)
RETURNS SETOF tbl_vendor LANGUAGE SQL
AS $$
    SELECT * FROM tbl_vendor
    WHERE name ILIKE '%'||"vendor_name"||'%'
    ORDER BY name ASC, vendor_id DESC;
$$;

CREATE OR REPLACE FUNCTION get_vendors_in_range("skip" INT, "count" INT)
RETURNS SETOF tbl_vendor LANGUAGE SQL
AS $$
    SELECT * FROM tbl_vendor
    ORDER BY
        name ASC,
        vendor_id DESC
    LIMIT "count" OFFSET "skip";
$$;

CREATE OR REPLACE FUNCTION get_vendor_count()
RETURNS bigint LANGUAGE SQL
AS $$
    SELECT COUNT(*) FROM tbl_vendor;
$$;

CREATE OR REPLACE FUNCTION get_product("product_name" TEXT)
RETURNS SETOF tbl_product LANGUAGE SQL
AS $$
    SELECT * FROM tbl_product
    WHERE name="product_name";
$$;

CREATE OR REPLACE FUNCTION get_product_by_id("prod_id" INT)
RETURNS SETOF tbl_product LANGUAGE SQL
AS $$
    SELECT * FROM tbl_product
    WHERE product_id="prod_id";
$$;

CREATE OR REPLACE FUNCTION get_operating_system("id_operating_system" INT)
RETURNS SETOF tbl_operating_system LANGUAGE SQL
AS $$
    SELECT * FROM tbl_operating_system
    WHERE operating_system_id="id_operating_system";
$$;

CREATE OR REPLACE FUNCTION get_cwe_for_cve("cve_id" VARCHAR(32))
RETURNS SETOF tbl_cwe LANGUAGE SQL
AS $$
    SELECT c.* FROM tbl_cwe AS c
    LEFT JOIN xref_cve_cwe AS xr ON xr.id_cwe=c.cwe_id
    WHERE xr.id_cve="cve_id";
$$;

CREATE OR REPLACE FUNCTION get_all_vendors()
RETURNS SETOF tbl_vendor LANGUAGE SQL
AS $$
    SELECT * FROM tbl_vendor;
$$;

CREATE OR REPLACE FUNCTION get_all_products()
RETURNS SETOF tbl_product LANGUAGE SQL
AS $$
    SELECT * FROM tbl_product;
$$;

CREATE OR REPLACE FUNCTION get_all_users()
RETURNS SETOF tbl_user LANGUAGE SQL
AS $$
    SELECT * FROM tbl_user;
$$;

CREATE OR REPLACE FUNCTION get_products_for_vendor("vendor_name" TEXT)
RETURNS SETOF tbl_product LANGUAGE SQL
AS $$
    SELECT p.* FROM tbl_product AS p
    LEFT JOIN tbl_vendor AS v ON v.vendor_id=p.id_vendor
    WHERE v.name="vendor_name";
$$;

CREATE OR REPLACE FUNCTION get_all_operating_system_types()
RETURNS TABLE(os_type TEXT) LANGUAGE SQL
AS $$
    SELECT DISTINCT os_type FROM tbl_operating_system;
$$;

CREATE OR REPLACE FUNCTION get_operating_systems_for_type("type" TEXT)
    RETURNS TABLE(name TEXT) LANGUAGE SQL
AS $$
    SELECT DISTINCT name FROM tbl_operating_system
    WHERE os_type="type";
$$;

CREATE OR REPLACE FUNCTION get_product_ids_for_operating_system_name("os_name" TEXT)
    RETURNS TABLE(product_id INT) LANGUAGE SQL
AS $$
    SELECT id_product FROM tbl_operating_system
    WHERE name="os_name";
$$;

CREATE OR REPLACE FUNCTION select_user("user_email" TEXT)
    RETURNS TABLE(id INT) LANGUAGE SQL
AS $$
    SELECT user_id FROM tbl_user
    WHERE email="user_email";
$$;

CREATE OR REPLACE FUNCTION insert_cve(
        "cve_id" VARCHAR(32),
        "description" TEXT,
        "cvss" REAL,
        "published_date" TIMESTAMP,
        "last_modified_date" TIMESTAMP,
        "reference_links" TEXT DEFAULT NULL,
        "exploitability_score" REAL DEFAULT NULL,
        "impact_score" REAL DEFAULT NULL,
        "severity" VARCHAR(16) DEFAULT NULL,
        "cvss_access_vector" VARCHAR(16) DEFAULT NULL,
        "cvss_vector_string" VARCHAR(64) DEFAULT NULL,
        "cvss_access_complexity" VARCHAR(16) DEFAULT NULL,
        "cvss_authentication" VARCHAR(16) DEFAULT NULL,
        "cvss_confidentiality_impact" VARCHAR(16) DEFAULT NULL,
        "cvss_integrity_impact" VARCHAR(16) DEFAULT NULL,
        "cvss_availability_impact" VARCHAR(16) DEFAULT NULL
    )
RETURNS VARCHAR(32) LANGUAGE SQL
AS $$
    INSERT INTO tbl_cve(
        cve_id,
        description,
        cvss,
        reference_links,
        exploitability_score,
        impact_score,
        severity,
        cvss_access_vector,
        cvss_vector_string,
        cvss_access_complexity,
        cvss_authentication,
        cvss_confidentiality_impact,
        cvss_integrity_impact,
        cvss_availability_impact,
        published_date,
        last_modified_date
    )
    VALUES (
            "cve_id",
            "description",
            "cvss",
            "reference_links",
            "exploitability_score",
            "impact_score",
            "severity",
            "cvss_access_vector",
            "cvss_vector_string",
            "cvss_access_complexity",
            "cvss_authentication",
            "cvss_confidentiality_impact",
            "cvss_integrity_impact",
            "cvss_availability_impact",
            "published_date",
            "last_modified_date"
        )
    RETURNING cve_id
$$;

CREATE OR REPLACE FUNCTION update_cve(
        "cve_id_" VARCHAR(32),
        "description_" TEXT,
        "cvss_" REAL,
        "published_date_" TIMESTAMP,
        "last_modified_date_" TIMESTAMP,
        "reference_links_" TEXT DEFAULT NULL,
        "exploitability_score_" REAL DEFAULT NULL,
        "impact_score_" REAL DEFAULT NULL,
        "severity_" VARCHAR(16) DEFAULT NULL,
        "cvss_access_vector_" VARCHAR(16) DEFAULT NULL,
        "cvss_vector_string_" VARCHAR(64) DEFAULT NULL,
        "cvss_access_complexity_" VARCHAR(16) DEFAULT NULL,
        "cvss_authentication_" VARCHAR(16) DEFAULT NULL,
        "cvss_confidentiality_impact_" VARCHAR(16) DEFAULT NULL,
        "cvss_integrity_impact_" VARCHAR(16) DEFAULT NULL,
        "cvss_availability_impact_" VARCHAR(16) DEFAULT NULL
    )
RETURNS VOID LANGUAGE SQL
AS $$
    UPDATE tbl_cve SET
        description="description_",
        cvss="cvss_",
        reference_links="reference_links_",
        exploitability_score="exploitability_score_",
        impact_score="impact_score_",
        severity="severity_",
        cvss_access_vector="cvss_access_vector_",
        cvss_vector_string="cvss_vector_string_",
        cvss_access_complexity="cvss_access_complexity_",
        cvss_authentication="cvss_authentication_",
        cvss_confidentiality_impact="cvss_confidentiality_impact_",
        cvss_integrity_impact="cvss_integrity_impact_",
        cvss_availability_impact="cvss_availability_impact_",
        published_date="published_date_",
        last_modified_date="last_modified_date_"
    WHERE cve_id="cve_id_";
$$;

CREATE OR REPLACE FUNCTION insert_cwe("cwe_id" VARCHAR(16), "name" VARCHAR(256), "description" TEXT)
RETURNS VARCHAR(16) LANGUAGE SQL
AS $$
    INSERT INTO tbl_cwe(cwe_id, name, description)
    VALUES ("cwe_id", "name", "description")
    RETURNING cwe_id
$$;

CREATE OR REPLACE FUNCTION insert_capec(
        "capec_id" VARCHAR(32),
        "name" VARCHAR(256),
        "description" TEXT,
        "prerequisites" TEXT,
        "mitigations" TEXT
    )
RETURNS VARCHAR(32) LANGUAGE SQL
AS $$
    INSERT INTO tbl_capec(capec_id, name, description, prerequisites, mitigations)
    VALUES ("capec_id", "name", "description", "prerequisites", "mitigations")
    RETURNING capec_id
$$;

CREATE OR REPLACE FUNCTION insert_user("email" VARCHAR(320))
RETURNS integer LANGUAGE SQL
AS $$
    INSERT INTO tbl_user(email, created_at)
    VALUES ("email", CURRENT_TIMESTAMP)
    RETURNING user_id
$$;

CREATE OR REPLACE FUNCTION insert_subscription(
        "custom_regex" TEXT,
        "cvss" REAL,
        "confirmed" BOOLEAN,
        "id_user" INT,
        "id_product" INT,
        "id_vendor" INT
    )
RETURNS integer LANGUAGE SQL
AS $$
    INSERT INTO tbl_subscription
    (custom_regex, cvss, created_at, confirmed, id_user, id_product, id_vendor)
    VALUES
    ("custom_regex", "cvss", CURRENT_TIMESTAMP, "confirmed", "id_user", "id_product", "id_vendor")
    RETURNING subscription_id
$$;

CREATE OR REPLACE FUNCTION insert_cve_top_ten("id_cve" VARCHAR(32))
RETURNS integer LANGUAGE SQL
AS $$
    INSERT INTO tbl_cve_top_ten(id_cve)
    VALUES ("id_cve")
    RETURNING id
$$;

CREATE OR REPLACE FUNCTION insert_vendor_top_ten("id_vendor" INT)
RETURNS integer LANGUAGE SQL
AS $$
    INSERT INTO tbl_vendor_top_ten(id_vendor)
    VALUES ("id_vendor")
    RETURNING id
$$;

CREATE OR REPLACE FUNCTION insert_vendor("name" TEXT)
RETURNS integer LANGUAGE SQL
AS $$
    INSERT INTO tbl_vendor(name)
    VALUES ("name")
    RETURNING vendor_id
$$;

CREATE OR REPLACE FUNCTION insert_product("name" TEXT, "id_vendor" INT)
RETURNS integer LANGUAGE SQL
AS $$
    INSERT INTO tbl_product(name, id_vendor)
    VALUES ("name", "id_vendor")
    RETURNING product_id
$$;

CREATE OR REPLACE FUNCTION insert_operating_system("name" TEXT, "id_product" INT, "os_type" TEXT)
RETURNS integer LANGUAGE SQL
AS $$
    INSERT INTO tbl_operating_system(name, id_product, os_type)
    VALUES ("name", "id_product", "os_type")
    RETURNING operating_system_id
$$;

CREATE OR REPLACE FUNCTION insert_cwe_capec("id_cwe" VARCHAR(16), "id_capec" VARCHAR(32))
RETURNS integer LANGUAGE SQL
AS $$
    INSERT INTO xref_cwe_capec(id_cwe, id_capec)
    VALUES ("id_cwe", "id_capec")
    RETURNING id
$$;

CREATE OR REPLACE FUNCTION insert_cve_cwe("id_cve" VARCHAR(32), "id_cwe" VARCHAR(16))
RETURNS integer LANGUAGE SQL
AS $$
    INSERT INTO xref_cve_cwe(id_cve, id_cwe)
    VALUES ("id_cve", "id_cwe")
    RETURNING id
$$;

CREATE OR REPLACE FUNCTION insert_cve_product("id_cve" VARCHAR(32), "id_product" INT)
RETURNS integer LANGUAGE SQL
AS $$
    INSERT INTO xref_cve_product(id_cve, id_product)
    VALUES ("id_cve", "id_product")
    RETURNING id
$$;

CREATE OR REPLACE FUNCTION confirm_subscription("id" INT)
RETURNS void LANGUAGE SQL
AS $$
  UPDATE tbl_subscription
    SET confirmed = TRUE
    WHERE subscription_id = "id";
$$;

CREATE OR REPLACE FUNCTION delete_subscription("id" INT)
RETURNS void LANGUAGE SQL
AS $$
  DELETE FROM tbl_subscription
    WHERE subscription_id = "id";
$$;

CREATE OR REPLACE FUNCTION delete_user("email" TEXT)
RETURNS void LANGUAGE SQL
AS $$
  DELETE FROM tbl_user
    WHERE email = "email";
$$;

CREATE OR REPLACE FUNCTION drop_database_data()
RETURNS void LANGUAGE SQL
AS $$
    DELETE FROM xref_cve_cwe;
    DELETE FROM xref_cwe_capec;
    DELETE FROM tbl_cve_top_ten;
    DELETE FROM tbl_vendor_top_ten;
    DELETE FROM tbl_operating_system;
    DELETE FROM tbl_subscription;
    DELETE FROM tbl_user;
    DELETE FROM tbl_cwe;
    DELETE FROM tbl_capec;
    DELETE FROM xref_cve_product;
    DELETE FROM tbl_cve;
    DELETE FROM tbl_product;
    DELETE FROM tbl_vendor;
$$;

DROP DATABASE IF EXISTS epsilon_test;
CREATE DATABASE epsilon_test WITH TEMPLATE epsilon;

