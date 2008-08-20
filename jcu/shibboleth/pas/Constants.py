#Properties Data
user_cn_attribute = 'User_Common_Name_Attribute'
idp_identifier_attribute='IDP_Attribute'
shib_config_dir='Shibboleth_Config_Dir'

#Properties Valuet
default_user_cn_attribute_value = 'HTTP_SHIB_PERSON_COMMONNAME'
default_idp_identifier_attribute_value = 'HTTP_SHIB_IDENTITY_PROVIDER'
default_shib_config_dir = '/etc/shibboleth'

#Session Key
session_id = 'session_id'
#defaultProperties = {max_brackets:[6, 'int'],
#                     user_uid_attribute: ['HTTP_SHIB_PERSON_UID','string'],
#                    user_cn_attribute: ['HTTP_SHIB_PERSON_COMMONNAME','string']}
#defaultProperties = {max_brackets:[6, 'int'],
#                      user_uid_attribute: ['HTTP_SHIB_REMOTE_USER','string'],
#                      user_cn_attribute: ['HTTP_SHIB_PERSON_COMMONNAME','string']}

#Mapping Manager Data
EXPRESSIONS = {0:'==', 1:'!=', 2:'>', 3:'=>', 4:'<', 5:'<=', 6:'matches', 7:'!matches', 8:'search', 9:'!search', 10:'exists', 11:'!exists'}
EXP_CODE    = {0:' attributes[%(1)s] == %(2)s ',
               1:' attributes[%(1)s] != %(2)s ',
               2:' attributes[%(1)s] > %(2)s ',
               3:' attributes[%(1)s] => %(2)s ',
               4:' attributes[%(1)s] < %(2)s ',
               5:' attributes[%(1)s] <= %(2)s ',
               6:' (re.compile(%(2)s).match(attributes[%(1)s]) != None) ',
               7:' (re.compile(%(2)s).match(attributes[%(1)s]) == None) ',
               8:' (re.compile(%(2)s).search(attributes[%(1)s]) != None) ',
               9:' (re.compile(%(2)s).search(attributes[%(1)s]) == None) ',
              10:' attributes.has_key(%(1)s) ',
              11:' (not (attributes.has_key(%(1)s))) '}

#This list contains the ids of all the regular expression operations.
#These operations need an extra check during code generation to
#ensure that the regular expression is valid.
REGEX_EXP   = [6, 7, 8, 9]

BOOL_EXPRESSIONS = {0: 'AND', 1: 'OR', 2:'NAND', 3:'NOR', 4:'XOR'}
BOOL_CODE = {0: ' %s and \\\n    %s ', 1: ' %s or \\\n    %s ', 2:' (not (%s and \\\n    %s)) ', 3:' (not (%s or \\\n    %s)) ', 4:'%s ^ \\\n    %s'}

#These constants are used in zpts.
action="manage_mappings"
op_type="op_type"
mapping="mapping"
op_add_item="add_item"
op_del_item="del_item"
op_manage_item="manage_item"
op_export_mapping="export_mapping"
op_import_mapping="import_mapping"
mapping_item="item"

opening_bracket_element="opening_bracket"
closing_bracket_element="closing_bracket"
var_name_element="var_name"
var_value_element="var_value"
op_type_value_element="opp_type"
bool_row_op_element="brop"
del_row_element="del_row"
add_row_element="add_row"
add_row_count_element="add_row_count"
save_map_element="save_map"
uploaded_file_element="uploaded_file"
ignore_hash_element="ignore_hash"
ignore_name_element="ignore_name"
message_element="message"

#These constants represent the position that each item ocupies
#in the list containing the expressions for the Role/Group
#mappers.
OBPos  = 0  #Opening Bracket Position
SVNPos = 1  #S? Variable Name Position
OTPos  = 2  #Operator Type Position
SVVPos = 3  #S? Variable Value Position
CBPos  = 4  #Closing Bracket Position
BOTPos = 5  #Boolean Operator Type Position

#The Names of the Mappers
RoleM = "Role"
GroupM = "Group"
ExportImportM="ExportImport"
