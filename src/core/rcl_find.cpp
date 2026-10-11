#include "rcl_find.h"
#include "rcl_syms.h"
#include "../scan/rcl_objects.h"
#include "rcl_log.h"
#include <map>
#include <stdio.h>
#include <set>
#include <string>

namespace rcl
{

const Target kTargets[] = {
    {"LogicBattleModeClient_update", 0, "LogicBattleModeClient", 0xc21a5c},
    {"BattleMode_getInstance", 0, "BattleMode", 0x9bb5e8},
    {"LogicGameObjectClient_getX", 0, "LogicGameObjectClient", 0xb5e44c},
    {"LogicGameObjectClient_getY", 0, "LogicGameObjectClient", 0xb5e454},
    {"LogicGameObjectClient_getZ", 0, "LogicGameObjectClient", 0xb5e45c},
    {"LogicBattleModeClient_getOwnCharacter", 0, "LogicBattleModeClient", 0xc239b0},
    {"BattleScreen_activateSkill", 0, "BattleScreen", 0x85ce88},
    {"StringCtor", 1, "String", 0xe9779c},
    {"Gui_showFloaterTextAtDefaultPos", 0, "Gui", 0x87ab5c},
    {"LogicBattleModeClient_getOwnPlayerTeam", 0, "LogicBattleModeClient", 0xc23608},
    {"LogicGameObjectClient_getGlobalID", 0, "LogicGameObjectClient", 0xb5e3f8},
    {"LogicGameObjectClient_getData", 0, "LogicGameObjectClient", 0xb5e12c},
    {"LogicProjectileData_getRadius", 0, "LogicProjectileData", 0xafb170},
    {"LogicProjectileData_getSpeed", 0, "LogicProjectileData", 0xafb0f0},
    {"LogicProjectileData_getRendering", 0, "LogicProjectileData", 0xafb2c4},
    {"LogicCharacterData_getCollisionRadius", 0, "LogicCharacterData", 0xab3e8c},
    {"decoratedTextFieldSetPlayerName", 1, "DecoratedTextField", 0x5cb120},
    {"TextField_setText_ui", 0, "TextField", 0x5cb120},
    {"TextField_setText", 0, "TextField", 0xce46f0},
    {"handleJoystick", 1, "handleJoystick", 0x5baba0},
    {"ClientInput_constructor_int", 1, "ClientInput", 0xbe6228},
    {"ClientInputManager_addInput", 0, "ClientInputManager", 0x7efc30},
    {"LogicBattleModeClient_setClientPredictionMoveTo", 0, "LogicBattleModeClient", 0xc23b14},
    {"Sprite_Sprite", 1, "Sprite", 0xcc6864},
    {"TileMap_Width", 1, "TileMap", 0xc4},
    {"TileMap_Height", 1, "TileMap", 0xc8},
    {"TileMap_TilesArray", 1, "TileMap", 0x20},
    {"TileTypeData_BlocksMovement", 1, "TileTypeData", 0x56},
    {"TileTypeData_BlocksProjectiles", 1, "TileTypeData", 0x57},
    {"LogicTileData__blocksProjectiles", 0, "LogicTileData", 0xb21720},
    {"BattleMode_objectManagerPtr", 1, "BattleMode", 0x28},
    {"BattleMode_clientInputManager", 1, "BattleMode", 0x58},
    {"ObjectManager_objectsArray", 1, "ObjectManager", 0x0},
    {"ObjectManager_count", 1, "ObjectManager", 0xc},
    {"ObjectManager_ptrStride", 1, "ObjectManager", 0x8},
    {"GameObj_team", 1, "GameObj", 0x40},
    {"LogicGameObjectClient_ownerIndex", 1, "LogicGameObjectClient", 0x3C},
    {"GameObj_deadFlag", 1, "GameObj", 0xd0},
    {"CharData_speed", 1, "CharData", 0x1c4},
    {"CharData_brawlerId", 1, "CharData", 0x18},
    {"Projectile_isIndirect", 0, "Projectile", 0xb8},
    {"Projectile_angle", 1, "Projectile", 0x1d4},
    {"LogicCharacterClientOwn_speedBuff", 1, "LogicCharacterClientOwn_", 0x1fc},
    {"LogicProjectileClient_ownerTeam", 1, "LogicProjectileClient", 0x40},
    {"LogicProjectileClient_dataName", 1, "LogicProjectileClient", 0x58},
    {"Joy_currentX", 1, "Joy", 0x94},
    {"Joy_currentY", 1, "Joy", 0x98},
    {"Joy_centerX", 1, "Joy", 0x9c},
    {"Joy_centerY", 1, "Joy", 0xa0},
    {"Joy_isDragging", 0, "Joy", 0x10},
    {"ScString_length", 1, "ScString", 0x4},
    {"ScString_data", 1, "ScString", 0x8},
    {"ScString_destruct", 1, "ScString", 0xe9768c},
    {"ResourceManager__isResourceLoaded", 0, "ResourceManager", 0xc85f54},
    {"GameMain__update", 0, "GameMain", 0x4d0224},
    {"DecalManager__DecalManager", 0, "DecalManager", 0x5318bc},
    {"LogicProjectileData__IsOwnTeamProjectile", 0, "LogicProjectileData", 0x531fa4},
    {"GameObjectManager__GameObjectManager", 0, "GameObjectManager", 0x532f90},
    {"Projectile_ctor", 0, "Projectile", 0x5391f4},
    {"Projectile__update", 0, "Projectile", 0x539c04},
    {"RenderSystem__RenderSystem", 0, "RenderSystem", 0x53c57c},
    {"CombatHUD__toggleEditing", 0, "CombatHUD", 0x598fa4},
    {"BattleScreen__updateCameraParameters", 0, "BattleScreen", 0x8572d4},
    {"Character__updateHealthBar", 0, "Character", 0x5a51ec},
    {"CombatHUD__setShootStickState", 0, "CombatHUD", 0x5b6dfc},
    {"CombatHUD__setMoveStickState", 0, "CombatHUD", 0x5b6eac},
    {"GUI__getDefaultFloaterPos", 0, "Gui", 0x85c8bc},
    {"GUI__showFloaterTextAt", 0, "Gui", 0x5c4be4},
    {"GUI__showPopup", 0, "Gui", 0x5c5938},
    {"GameButtonCtor", 1, "GameButton", 0x5caacc},
    {"DropGUIContainer__ctorFromExport", 0, "DropGUIContainer", 0x50da1c},
    {"DropGUIContainer_movieClip", 1, "DropGUIContainer", 0x80},
    {"GameSliderComponent__GameSliderComponent", 0, "GameSliderComponent", 0x5cee18},
    {"GameSliderComponent__setValueBounds", 0, "GameSliderComponent", 0x5cf61c},
    {"MapEditorModifierItem__MapEditorModifierItem", 0, "MapEditorModifierItem", 0x72dd28},
    {"MapEditorModifierPopup__MapEditorModifierPopup", 0, "MapEditorModifierPopup", 0x72ec40},
    {"MapEditorModifierPopup__addModifierItem", 0, "MapEditorModifierPopup", 0x72f5dc},
    {"PopupBase__PopupBase", 0, "PopupBase", 0x73eb90},
    {"MessageManager__receiveMessage", 0, "MessageManager", 0x80f464},
    {"BattleScreen__BattleScreen", 0, "BattleScreen", 0x8532bc},
    {"BattleScreen__stopWithStick", 0, "BattleScreen", 0x859bb0},
    {"BattleScreen__handleTouchReleased", 0, "BattleScreen", 0x85b714},
    {"BattleScreen__update", 0, "BattleScreen", 0x59c74c},
    {"BattleScreen_spectateWidget", 0, "BattleScreen", 0x3e8},
    {"BattleScreen_spectateTextField", 0, "BattleScreen", 0x3f8},
    {"BattleScreen__updateAutoshoot", 0, "BattleScreen", 0x861dd0},
    {"BattleScreen_getClosestTargetForAutoshoot", 0, "BattleScreen", 0x876eb0},
    {"BattleScreen__updateMovement", 0, "BattleScreen", 0x863b7c},
    {"BattleScreen__tryToActivateSkill", 0, "BattleScreen", 0x86c4a0},
    {"BattleScreen__shouldShowAccessoryButton", 0, "BattleScreen", 0x86eb74},
    {"BattleScreen__calculateProjectilePath", 0, "BattleScreen", 0x873264},
    {"BattleScreen__joystickToWorld", 0, "BattleScreen", 0x877b54},
    {"GameScreen__getLogicBattle", 0, "GameScreen", 0x87aa4c},
    {"MapEditorScreen__initRenderSystem", 0, "MapEditorScreen", 0x88e5d0},
    {"MapEditorScreen__initItems", 0, "MapEditorScreen", 0x88e734},
    {"MapEditorScreen__initCharacters", 0, "MapEditorScreen", 0x88e800},
    {"GameSettings__isFixedJoystickEnabled", 0, "GameSettings", 0x9a91a4},
    {"BattleMode__enter", 0, "BattleMode", 0x9bcea4},
    {"BattleMode__addResourcesToLoad", 0, "BattleMode", 0x9bd0fc},
    {"GameStateManager__getInstance", 0, "GameStateManager", 0x9c4838},
    {"GameStateManager__isState", 0, "GameStateManager", 0x9c55ec},
    {"HomeMode__getInstance", 0, "HomeMode", 0x9c79d0},
    {"StringTable__getMovieClip", 0, "StringTable", 0x9d6a94},
    {"MovieClipHelper__setTextAndScaleIfNecessary", 0, "MovieClipHelper", 0xa021d0},
    {"LogicTile__setData", 0, "LogicTile", 0xa51d84},
    {"LogicTileMap__LogicTileMap", 0, "LogicTileMap", 0x5330bc},
    {"LogicTileMap__isPlayerLineOfSightClear", 0, "LogicTileMap", 0xa56df8},
    {"LogicTileMap__isPlayerLineOfSightClear1", 0, "LogicTileMap", 0xa56e28},
    {"LogicDataTables__getOpenTileData", 0, "LogicDataTables", 0xad6220},
    {"LogicDataTables__getBaseTileData", 0, "LogicDataTables", 0xad6274},
    {"LogicDataTables__getSiegeBoltTileData", 0, "LogicDataTables", 0xad62c8},
    {"LogicProjectileData__isBeam", 0, "LogicProjectileData", 0xafb2a4},
    {"LogicCharacterData_getSpeed", 0, "LogicCharacterData", 0xab3c40},
    {"LogicProjectileData__getNumEarlyTicks", 0, "LogicProjectileData", 0xafb588},
    {"LogicSkillData__getActiveTime", 0, "LogicSkillData", 0xb0e34c},
    {"LogicSkillData__getRechargeTime", 0, "LogicSkillData", 0xb0e660},
    {"LogicSkillData__getMaxCharge", 0, "LogicSkillData", 0xb0e670},
    {"LogicSkillData__getMsBetweenAttacks", 0, "LogicSkillData", 0xb0e698},
    {"LogicSkillData__getCastingRange", 0, "LogicSkillData", 0xb0e384},
    {"LogicTileData__blocksMovement", 0, "LogicTileData", 0xb21718},
    {"LogicCharacterClient__getCarryableData", 0, "LogicCharacterClient", 0xb30b88},
    {"LogicCharacterClient__getWeaponSkill", 0, "LogicCharacterClient", 0xb319f8},
    {"LogicCharacterClient__canMoveAndUseThisSkillSimultaneously", 0, "LogicCharacterClient", 0xb31a10},
    {"LogicCharacterClient__getLinkedCarryable", 0, "LogicCharacterClient", 0xb31d3c},
    {"LogicCharacterClient__getCurrentActiveOrCastingSkill", 0, "LogicCharacterClient", 0xb3263c},
    {"LogicCharacterClient__getSkillAt", 0, "LogicCharacterClient", 0xb31970},
    {"LogicCharacterClient_hyperActive", 1, "LogicCharacterClient", 0x31e},
    {"LogicCharacterClient_body", 1, "LogicCharacterClient", 0x3e8},
    {"LogicSkillClient__getData", 0, "LogicSkillClient", 0xb7ad4c},
    {"LogicSkillClient__canActivate", 0, "LogicSkillClient", 0xb7aecc},
    {"LogicSkillData__getBehaviour", 0, "LogicSkillData", 0xb0eb7c},
    {"LogicSkillData__getLinkedSkill", 0, "LogicSkillData", 0xb0eb8c},
    {"LogicSkillData_kind", 1, "LogicSkillData", 0x1ac},
    {"SkillCommandTypeTable", 2, "SkillCommandTypeTable", 0x184720},
    {"ClientInput_skillData", 1, "ClientInput", 0x40},
    {"LogicCharacterClientOwn__clientPredictionPauseMovementForSkillCasting", 0, "LogicCharacterClientOwn_", 0xb346f0},
    {"LogicCharacterClientOwn__clientPredictionUpdateAttackDirection", 0, "LogicCharacterClientOwn_", 0xb34758},
    {"LogicGameObjectManagerClient__LogicGameObjectManagerClient", 0, "LogicGameObjectManagerClient", 0xb5e78c},
    {"LogicGameObjectManagerClient__getGameObjects", 0, "LogicGameObjectManagerClient", 0xb5eba8},
    {"LogicGameObjectManagerClient__findGameObject", 0, "LogicGameObjectManagerClient", 0xb61ca4},
    {"LogicGameObjectServer__getData", 0, "LogicGameObjectServer", 0xb6acac},
    {"LogicProjectileServer__shootProjectile", 0, "LogicProjectileServer", 0xb78a98},
    {"LogicProjectileServer__runEarlyTicks", 0, "LogicProjectileServer", 0xb79a58},
    {"GlobalID__getInstanceID", 0, "GlobalID", 0xbb3d6c},
    {"LogicPlayerMap__save", 0, "LogicPlayerMap", 0xbbccdc},
    {"LogicPlayerMapUtil__tileDataToTileCode", 0, "LogicPlayerMapUtil", 0xbc0af0},
    {"AnalyticEvent__AnalyticEvent", 0, "AnalyticEvent", 0xbda1d4},
    {"AnalyticEvent__setString", 0, "AnalyticEvent", 0xbda2c4},
    {"LogicBattleModeClient__LogicBattleModeClient", 0, "LogicBattleModeClient", 0xc211f0},
    {"LogicBattleModeClient__setRandomSeed", 0, "LogicBattleModeClient", 0xc213f4},
    {"LogicBattleModeClient__setPlayerAvatar", 0, "LogicBattleModeClient", 0xc2196c},
    {"LogicBattleModeClient__getOwnPlayerIndex", 0, "LogicBattleModeClient", 0xc23600},
    {"LogicBattleModeClient__getTileMap", 0, "LogicBattleModeClient", 0xc23930},
    {"SetClientPrediction", 1, "SetClientPrediction", 0xc23b14},
    {"ScrollArea__scrollTo", 0, "ScrollArea", 0xc7a8a4},
    {"StringTable_getMovieClip", 0, "StringTable", 0xc86174},
    {"DisplayObject__setXY", 0, "DisplayObject", 0xcaf2b0},
    {"DisplayObject__removeFromParent", 0, "DisplayObject", 0xcaf60c},
    {"MovieClip__getTextFieldByName", 0, "MovieClip", 0xcb5f14},
    {"Sprite__addChild", 0, "Sprite", 0xcc6a80},
    {"Sprite__addChildAt", 0, "Sprite", 0xcc6a88},
    {"Sprite__removeChild", 0, "Sprite", 0xcc6d64},
    {"ScrollArea__updateBounds", 0, "ScrollArea", 0xce9834},
    {"ScrollArea__addContent", 0, "ScrollArea", 0x6d6220},
    {"ScrollArea__removeAllContent", 0, "ScrollArea", 0xce9ae0},
    {"CSVRow__getIntegerValueAt", 0, "CSVRow", 0xcf73bc},
    {"CSVRow__getName", 0, "CSVRow", 0xcf734c},
    {"CSVRow__getValueAt", 0, "CSVRow", 0xcf73cc},
    {"CSVRow__getBooleanValueAt", 0, "CSVRow", 0xcf73ac},
    {"CSVTable__getColumnIndexByName", 0, "CSVTable", 0xcf7bcc},
    {"LogicJSONObject__put", 0, "LogicJSONObject", 0xc8771c},
    {"LogicRandom__setIteratedRandomSeed", 0, "LogicRandom", 0xd017e4},
    {"LogicCompressedString__LogicCompressedString", 0, "LogicCompressedString", 0xd15970},
    {"LogicLongToCodeConverterUtil__LogicLongToCodeConverterUtil", 0, "LogicLongToCodeConverterUtil", 0xd2fc50},
    {"LogicLongToCodeConverterUtil__convert", 0, "LogicLongToCodeConverterUtil", 0xd170cc},
    {"LogicLongToCodeConverterUtil__toCode", 0, "LogicLongToCodeConverterUtil", 0x845d84},
    {"ResourceListener__addFile", 0, "ResourceListener", 0xd349b8},
    {"String__format", 0, "String", 0xe9a370},
    {"FramerateManager__setSegment", 0, "FramerateManager", 0xea3c5c},
    {"FramerateManager__setLimit", 0, "FramerateManager", 0xea4160},
    {"FramerateManager_targetFps", 1, "FramerateManager", 0x12efa28},
    {"Application__copyString", 0, "Application", 0xf05ba0},
    {"HeroData_namePtr", 1, "HeroData", 0x48},
    {"BattleScreen_aimX", 1, "BattleScreen", 0xf7c},
    {"BattleScreen_aimY", 1, "BattleScreen", 0xf80},
    {"BattleScreen_aimTargetId", 1, "BattleScreen", 0xee4},
    {"BattleScreen_fireWrapperFn", 1, "BattleScreen", 0x85d09c},
    {"ClientInput_x", 1, "ClientInput", 0xc},
    {"ClientInput_y", 1, "ClientInput", 0x10},
    {"Message_port", 1, "Message", 0x90},
    {"Message_ipPtr", 1, "Message", 0x98},
    {"SockAddr_portHi", 1, "SockAddr", 0x2},
    {"SockAddr_portLo", 1, "SockAddr", 0x3},
    {"SockAddr_addr0", 0, "SockAddr", 0x4},
    {"SockAddr_addr1", 0, "SockAddr", 0x5},
    {"SockAddr_addr2", 0, "SockAddr", 0x6},
    {"SockAddr_addr3", 0, "SockAddr", 0x7},
    {"Stage_addChild", 0, "Stage", 0xccc9bc},
    {"Stage_spriteContainer", 1, "Stage", 0xa8},
    {"Sprite_childCount", 1, "Sprite", 0x4e},
    {"Sprite_childArray", 1, "Sprite", 0x50},
    {"GameButton_setText", 0, "GameButton", 0x5cb120},
    {"nativeCopyToClipboard", 1, "nativeCopyToClipboard", 0xea1000},
    {"BattleScreen_screenWidth", 1, "BattleScreen", 0x8e4},
    {"BattleScreen_screenHeight", 1, "BattleScreen", 0x8e8},
    {"BattleScreen_viewMatrix", 1, "BattleScreen", 0x848},
    {"BattleScreen_cameraMode", 1, "BattleScreen", 0x90c},
    {"ResourceManager__getCSV", 0, "ResourceManager", 0xc87d5c},
    {"VTABLE_PROJECTILE_DATA", 2, "VTABLE", 0x12080a0},
    {"StageInstanceGlobalPtr", 2, "Stage", 0x12f3cc0},
    {"MovieClip__gotoAndStopFrameIndex", 0, "MovieClip", 0xcb5070},
    {"MovieClip_gotoAndStop", 1, "MovieClip", 0xcb5070},
    {"BattleMode_hashEnabled", 1, "BattleMode", 0x70},
    {"BattleMode_hashKey", 1, "BattleMode", 0x60},
    {"ClientInput_typeConstantTable", 2, "ClientInput", 0x1f871c},
    {"ClientInput_hashInnerMask", 2, "ClientInput", 0x182f90},
    {"ClientInput_hashOuterMask", 2, "ClientInput", 0x183fb0},
    {"BattleScreen_autoFireBtnHeld", 1, "BattleScreen", 0xf49},
    {"BattleScreen_attackJoyHeld", 1, "BattleScreen", 0xf4a},
    {"BattleScreen_ultiJoyHeld", 1, "BattleScreen", 0xf4b},
    {"BattleScreen_movePending", 1, "BattleScreen", 0xf4f},
    {"LogicCharacterClient__isImmuneOrUntargetable", 0, "LogicCharacterClient", 0xb32474},
    {"operator_new", 2, "operator_new", 0x11a5760},
    {"TeamChatMessage_messageOffset", 1, "TeamChatMessage", 0x90},
    {"TeamChatMessage__ctor", 0, "TeamChatMessage", 0xbd33fc},
    {"TeamSetMemberReadyMessage_stateOffset", 1, "TeamSetMemberReadyMessage", 0x90},
    {"TeamSetMemberReadyMessage__ctor", 0, "TeamSetMemberReadyMessage", 0xbd6b50},
    {"MessageManager_instance", 2, "MessageManager", 0x12eed80},
    {"MessageManager__sendMessage", 0, "MessageManager", 0x80f37c},
    {"StartSpectateMessage__ctor", 0, "StartSpectateMessage", 0xc07af4},
    {"HashTagCodeGenerator__ctor", 0, "HashTagCodeGenerator", 0xc669f8},
    {"HashTagCodeGenerator__toId", 0, "HashTagCodeGenerator", 0xd15f80},
    {"Gui_getInstance", 0, "Gui", 0x5696d8},
    {"PiranhaMessage_ctor", 0, "PiranhaMessage", 0xd01bf4},
    {"LogicSkillData__getProjectileData", 0, "LogicSkillData", 0xb0e5ec},
    {"Name_setupDecorated", 0, "Name", 0x5c1644},
    {"Name_applyDecoration", 0, "Name", 0x5c16ac},
    {"LogicDataTables_tableArray", 2, "LogicDataTables", 0x12f0aa8},
    {"LogicDataTable_findByName", 0, "LogicDataTable", 0x30},
    {"GRADIENT_TABLE_INDEX", 2, "GRADIENT", 46},
    {"VTABLE_GRADIENT_DATA", 2, "VTABLE", 0x1206830},
    {"VTABLE_DECORATED_TEXT_FIELD", 2, "VTABLE", 0x11b1e48},
    {"VTABLE_TEXT_FIELD", 2, "VTABLE", 0x1218c28},
    {"DisplayObject_parent", 1, "DisplayObject", 0x38},
    {"DisplayObject_isMovieClipSlot", 0, "DisplayObject", 128},
    {"DecoratedTextField_marker", 1, "DecoratedTextField", 0x44},
    {"DecoratedTextField_text", 1, "DecoratedTextField", 0xe0},
    {"DecoratedTextField_gradient", 1, "DecoratedTextField", 0x268},
    {"AllianceManager__startSpectate", 0, "AllianceManager", 0x846cfc},
    {"AllianceManager_instance", 2, "AllianceManager", 0x12ef210},
    {"ClientInputMessage_sendMovement", 0, "ClientInputMessage", 0x592b20},
    {"CombatHUD__update", 0, "CombatHUD", 0x5a31bc},
    {"CombatHUD__sendPinCommand", 0, "CombatHUD", 0x59a2d4},
    {"CombatHUD__sendSprayCommand", 0, "CombatHUD", 0x59abdc},
    {"CustomButton_onButtonPressed", 0, "CustomButton", 0x5cb304},
    {"DisplayObject_x", 1, "DisplayObject", 0x20},
    {"DisplayObject_y", 1, "DisplayObject", 0x24},
    {"DisplayObject_scaleX", 1, "DisplayObject", 0x10},
    {"DisplayObject_scaleY", 1, "DisplayObject", 0x1c},
    {"DisplayObject_visible", 1, "DisplayObject", 0x8},
    {"GUI_spriteContainer", 1, "Gui", 0xa0},
    {"HashTagCodeGenerator__dtor", 0, "HashTagCodeGenerator", 0xc66a3c},
    {"HashTagCodeGenerator__isValid", 0, "HashTagCodeGenerator", 0xc66b64},
    {"LogicGameModeUtil__isTileOnPoisonArea", 0, "LogicGameModeUtil", 0xc69c30},
    {"LogicTileMap_getTile", 0, "LogicTileMap", 0xa53734},
    {"LogicProjectileClient_ctor", 0, "LogicProjectileClient", 0xb6f19c},
    {"LogicProjectileClient_destruct", 1, "LogicProjectileClient", 0xb6f20c},
    {"LogicProjectileClient_getData", 0, "LogicProjectileClient", 0xb6f56c},
    {"LogicProjectileClient_getTargetX", 0, "LogicProjectileClient", 0xb6f748},
    {"LogicProjectileClient_getTargetY", 0, "LogicProjectileClient", 0xb6f750},
    {"LogicProjectileData__getSpawnAreaEffect", 0, "LogicProjectileData", 0xafb254},
    {"AreaEffectData__getRadius", 0, "AreaEffectData", 0xa98614},
    {"AreaEffectData__getActiveTimeMs", 0, "AreaEffectData", 0xa9860c},
    {"LogicData_getName", 0, "LogicData", 0xac44f0},
    {"MapEditorScreen__updateCameraParameters", 0, "MapEditorScreen", 0x88e3c8},
    {"MovieClip__getChildClipByName", 0, "MovieClip", 0xcb5aac},
    {"MovieClip__setChildVisible", 0, "MovieClip", 0xcb6120},
    {"MovieClip_frameCount", 1, "MovieClip", 0x9e},
    {"Screen__getDpiClass", 0, "Screen", 0xea778c},
    {"Screen__getHeight", 0, "Screen", 0xea74b0},
    {"Screen__getWidth", 0, "Screen", 0xea74a4},
    {"Screen_heightGlobal", 2, "Screen", 0x1303184},
    {"Screen_widthGlobal", 2, "Screen", 0x1303180},
    {"VTABLE_CHARACTER_DATA", 2, "VTABLE", 0x1206000},
};
const size_t kTargetCount = sizeof(kTargets) / sizeof(kTargets[0]);

static void fmt_hex(char *dst, size_t cap, uint64_t v)
{
    snprintf(dst, cap, "0x%llx", (unsigned long long)v);
}

FindResult find_all(const Image &img, const Seeds &s)
{
    FindResult r;
    std::vector<Sym> syms;
    std::vector<std::string> norm;
    std::vector<Leaf> leaves;
    std::map<uint32_t, std::vector<uint64_t>> by_off;
    bool leaves_done = false;
    size_t i = 0;
    (void)s;
    load_symbols(img, syms);
    norm.reserve(syms.size());
    for (i = 0; i < syms.size(); i++)
    {
        std::string n;
        norm_key(syms[i].name.c_str(), n);
        norm.push_back(n);
    }
    for (i = 0; i < kTargetCount; i++)
    {
        const Target &t = kTargets[i];
        Found f{};
        char buf[32];
        int64_t hit = -1;
        f.key = t.key;
        f.kind = t.kind;
        hit = sym_match(syms, norm, t.key);
        if (hit >= 0)
        {
            f.value = syms[(size_t)hit].rva;
            f.src = "sym";
            f.info = syms[(size_t)hit].name;
            r.by_sym++;
            r.resolved++;
            r.items.push_back(f);
            continue;
        }
        if (t.seed != 0 && t.seed <= 0x1000u)
        {
            if (!leaves_done)
            {
                leaves_done = true;
                leaves = scan_leaf_getters(img);
                for (size_t k = 0; k < leaves.size(); k++)
                    by_off[leaves[k].off].push_back(leaves[k].fn);
            }
            f.value = t.seed;
            f.src = "field";
            fmt_hex(buf, sizeof buf, t.seed);
            f.info = buf;
            std::map<uint32_t, std::vector<uint64_t>>::iterator it = by_off.find((uint32_t)t.seed);
            if (it != by_off.end())
            {
                size_t shown = 0;
                for (size_t k = 0; k < it->second.size() && shown < 6; k++, shown++)
                {
                    fmt_hex(buf, sizeof buf, it->second[k]);
                    f.info += " leaf ";
                    f.info += buf;
                }
            }
            r.by_field++;
            r.resolved++;
            r.items.push_back(f);
            continue;
        }
        f.src = t.seed ? "hint" : "todo";
        fmt_hex(buf, sizeof buf, t.seed);
        f.info = buf;
        r.missing++;
        r.items.push_back(f);
    }
    RCL_LOGLN("[find] sym=%zu field=%zu unresolved=%zu symtab=%zu", r.by_sym, r.by_field, r.missing,
              syms.size());
    return r;
}

} // namespace rcl
