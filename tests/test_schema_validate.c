/*
 * smolclaw - JSON Schema validation tests
 */

#include "test_main.h"
#include "tools/schema_validate.h"
#include "cJSON.h"

/* ---------- Type validation ---------- */

static void test_type_string(void)
{
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "string");

    cJSON *val = cJSON_CreateString("hello");
    sc_schema_result_t r = sc_schema_validate(schema, val);
    ASSERT(r.valid, "string should validate as string");
    cJSON_Delete(val);

    val = cJSON_CreateNumber(42);
    r = sc_schema_validate(schema, val);
    ASSERT(!r.valid, "number should not validate as string");
    cJSON_Delete(val);

    r = sc_schema_validate(schema, NULL);
    ASSERT(!r.valid, "NULL should not validate as string");

    cJSON_Delete(schema);
}

static void test_type_integer(void)
{
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "integer");

    cJSON *val = cJSON_CreateNumber(42);
    sc_schema_result_t r = sc_schema_validate(schema, val);
    ASSERT(r.valid, "42 should validate as integer");
    cJSON_Delete(val);

    val = cJSON_CreateNumber(3.14);
    r = sc_schema_validate(schema, val);
    ASSERT(!r.valid, "3.14 should not validate as integer");
    cJSON_Delete(val);

    val = cJSON_CreateString("42");
    r = sc_schema_validate(schema, val);
    ASSERT(!r.valid, "string '42' should not validate as integer");
    cJSON_Delete(val);

    cJSON_Delete(schema);
}

static void test_type_number(void)
{
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "number");

    cJSON *val = cJSON_CreateNumber(3.14);
    sc_schema_result_t r = sc_schema_validate(schema, val);
    ASSERT(r.valid, "3.14 should validate as number");
    cJSON_Delete(val);

    val = cJSON_CreateNumber(42);
    r = sc_schema_validate(schema, val);
    ASSERT(r.valid, "42 should also validate as number");
    cJSON_Delete(val);

    cJSON_Delete(schema);
}

static void test_type_boolean(void)
{
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "boolean");

    cJSON *val = cJSON_CreateBool(1);
    sc_schema_result_t r = sc_schema_validate(schema, val);
    ASSERT(r.valid, "true should validate as boolean");
    cJSON_Delete(val);

    val = cJSON_CreateNumber(1);
    r = sc_schema_validate(schema, val);
    ASSERT(!r.valid, "number 1 should not validate as boolean");
    cJSON_Delete(val);

    cJSON_Delete(schema);
}

/* ---------- Required fields ---------- */

static void test_required_fields(void)
{
    /* Schema: { type: "object", properties: { path: {type: "string"} },
     *           required: ["path"] } */
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");
    cJSON *props = cJSON_AddObjectToObject(schema, "properties");
    cJSON *path_prop = cJSON_AddObjectToObject(props, "path");
    cJSON_AddStringToObject(path_prop, "type", "string");
    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("path"));

    /* Valid: path present */
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "path", "/tmp/test");
    sc_schema_result_t r = sc_schema_validate(schema, args);
    ASSERT(r.valid, "should pass with required field present");
    cJSON_Delete(args);

    /* Invalid: path missing */
    args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "other", "value");
    r = sc_schema_validate(schema, args);
    ASSERT(!r.valid, "should fail with required field missing");
    ASSERT(strstr(r.error, "path") != NULL, "error should mention 'path'");
    cJSON_Delete(args);

    /* Valid: extra fields OK */
    args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "path", "/tmp/test");
    cJSON_AddStringToObject(args, "extra", "value");
    r = sc_schema_validate(schema, args);
    ASSERT(r.valid, "extra fields should be allowed");
    cJSON_Delete(args);

    cJSON_Delete(schema);
}

/* ---------- Enum validation ---------- */

static void test_enum(void)
{
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "string");
    cJSON *enum_arr = cJSON_AddArrayToObject(schema, "enum");
    cJSON_AddItemToArray(enum_arr, cJSON_CreateString("add"));
    cJSON_AddItemToArray(enum_arr, cJSON_CreateString("list"));
    cJSON_AddItemToArray(enum_arr, cJSON_CreateString("remove"));

    cJSON *val = cJSON_CreateString("add");
    sc_schema_result_t r = sc_schema_validate(schema, val);
    ASSERT(r.valid, "'add' should match enum");
    cJSON_Delete(val);

    val = cJSON_CreateString("delete");
    r = sc_schema_validate(schema, val);
    ASSERT(!r.valid, "'delete' should not match enum");
    ASSERT(strstr(r.error, "delete") != NULL, "error should mention bad value");
    ASSERT(strstr(r.error, "add") != NULL, "error should list allowed values");
    cJSON_Delete(val);

    cJSON_Delete(schema);
}

/* ---------- Numeric constraints ---------- */

static void test_minimum_maximum(void)
{
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "integer");
    cJSON_AddNumberToObject(schema, "minimum", 1);
    cJSON_AddNumberToObject(schema, "maximum", 10);

    cJSON *val = cJSON_CreateNumber(5);
    sc_schema_result_t r = sc_schema_validate(schema, val);
    ASSERT(r.valid, "5 should be in range [1,10]");
    cJSON_Delete(val);

    val = cJSON_CreateNumber(1);
    r = sc_schema_validate(schema, val);
    ASSERT(r.valid, "1 should be at minimum (inclusive)");
    cJSON_Delete(val);

    val = cJSON_CreateNumber(10);
    r = sc_schema_validate(schema, val);
    ASSERT(r.valid, "10 should be at maximum (inclusive)");
    cJSON_Delete(val);

    val = cJSON_CreateNumber(0);
    r = sc_schema_validate(schema, val);
    ASSERT(!r.valid, "0 should be below minimum");
    ASSERT(strstr(r.error, "minimum") != NULL, "error should mention minimum");
    cJSON_Delete(val);

    val = cJSON_CreateNumber(11);
    r = sc_schema_validate(schema, val);
    ASSERT(!r.valid, "11 should be above maximum");
    ASSERT(strstr(r.error, "maximum") != NULL, "error should mention maximum");
    cJSON_Delete(val);

    cJSON_Delete(schema);
}

/* ---------- Property type validation ---------- */

static void test_property_types(void)
{
    /* Schema mimicking web_search: { query: string (required), count: integer } */
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");
    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *query = cJSON_AddObjectToObject(props, "query");
    cJSON_AddStringToObject(query, "type", "string");

    cJSON *count = cJSON_AddObjectToObject(props, "count");
    cJSON_AddStringToObject(count, "type", "integer");

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("query"));

    /* Valid: correct types */
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "query", "search term");
    cJSON_AddNumberToObject(args, "count", 5);
    sc_schema_result_t r = sc_schema_validate(schema, args);
    ASSERT(r.valid, "correct types should pass");
    cJSON_Delete(args);

    /* Invalid: count is string instead of integer */
    args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "query", "search term");
    cJSON_AddStringToObject(args, "count", "five");
    r = sc_schema_validate(schema, args);
    ASSERT(!r.valid, "string 'five' should fail integer validation");
    ASSERT(strstr(r.error, "count") != NULL, "error should mention 'count'");
    cJSON_Delete(args);

    /* Valid: optional field omitted */
    args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "query", "search term");
    r = sc_schema_validate(schema, args);
    ASSERT(r.valid, "omitting optional 'count' should pass");
    cJSON_Delete(args);

    cJSON_Delete(schema);
}

/* ---------- Full tool schema: cron_parameters style ---------- */

static void test_full_tool_schema(void)
{
    /* Simulate cron tool schema */
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");
    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *action = cJSON_AddObjectToObject(props, "action");
    cJSON_AddStringToObject(action, "type", "string");
    cJSON *action_enum = cJSON_AddArrayToObject(action, "enum");
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("add"));
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("list"));
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("remove"));

    cJSON *name = cJSON_AddObjectToObject(props, "name");
    cJSON_AddStringToObject(name, "type", "string");

    cJSON *seconds = cJSON_AddObjectToObject(props, "seconds");
    cJSON_AddStringToObject(seconds, "type", "number");

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("action"));

    /* Valid call */
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "add");
    cJSON_AddStringToObject(args, "name", "reminder");
    cJSON_AddNumberToObject(args, "seconds", 60);
    sc_schema_result_t r = sc_schema_validate(schema, args);
    ASSERT(r.valid, "valid cron call should pass");
    cJSON_Delete(args);

    /* Invalid: bad enum value */
    args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "delete");
    r = sc_schema_validate(schema, args);
    ASSERT(!r.valid, "invalid enum value should fail");
    cJSON_Delete(args);

    /* Invalid: missing required 'action' */
    args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "name", "reminder");
    r = sc_schema_validate(schema, args);
    ASSERT(!r.valid, "missing required 'action' should fail");
    cJSON_Delete(args);

    /* Invalid: seconds is string */
    args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "add");
    cJSON_AddStringToObject(args, "seconds", "sixty");
    r = sc_schema_validate(schema, args);
    ASSERT(!r.valid, "string 'sixty' should fail number validation");
    cJSON_Delete(args);

    cJSON_Delete(schema);
}

/* ---------- Edge cases ---------- */

static void test_null_schema(void)
{
    cJSON *val = cJSON_CreateString("anything");
    sc_schema_result_t r = sc_schema_validate(NULL, val);
    ASSERT(r.valid, "NULL schema should accept anything");
    cJSON_Delete(val);
}

static void test_empty_object(void)
{
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");
    /* No properties, no required */

    cJSON *args = cJSON_CreateObject();
    sc_schema_result_t r = sc_schema_validate(schema, args);
    ASSERT(r.valid, "empty object should match empty schema");
    cJSON_Delete(args);

    cJSON_Delete(schema);
}

static void test_array_items(void)
{
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "array");
    cJSON *items = cJSON_AddObjectToObject(schema, "items");
    cJSON_AddStringToObject(items, "type", "string");

    /* Valid: array of strings */
    cJSON *val = cJSON_CreateArray();
    cJSON_AddItemToArray(val, cJSON_CreateString("a"));
    cJSON_AddItemToArray(val, cJSON_CreateString("b"));
    sc_schema_result_t r = sc_schema_validate(schema, val);
    ASSERT(r.valid, "array of strings should pass");
    cJSON_Delete(val);

    /* Invalid: array with number */
    val = cJSON_CreateArray();
    cJSON_AddItemToArray(val, cJSON_CreateString("a"));
    cJSON_AddItemToArray(val, cJSON_CreateNumber(42));
    r = sc_schema_validate(schema, val);
    ASSERT(!r.valid, "array with number should fail string items check");
    ASSERT(strstr(r.error, "[1]") != NULL, "error should mention index [1]");
    cJSON_Delete(val);

    cJSON_Delete(schema);
}

/* ---------- Main ---------- */

int main(void)
{
    printf("test_schema_validate\n");

    RUN_TEST(test_type_string);
    RUN_TEST(test_type_integer);
    RUN_TEST(test_type_number);
    RUN_TEST(test_type_boolean);
    RUN_TEST(test_required_fields);
    RUN_TEST(test_enum);
    RUN_TEST(test_minimum_maximum);
    RUN_TEST(test_property_types);
    RUN_TEST(test_full_tool_schema);
    RUN_TEST(test_null_schema);
    RUN_TEST(test_empty_object);
    RUN_TEST(test_array_items);

    TEST_REPORT();
}
