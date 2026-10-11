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
    {"LogicBattleModeClient_update", 0, "LogicBattleModeClient", 0},
    {"BattleMode_getInstance", 0, "BattleMode", 0x8cdfd4},
    {"LogicGameObjectClient_getX", 0, "LogicGameObjectClient", 0xa23afc},
    {"LogicGameObjectClient_getY", 0, "LogicGameObjectClient", 0xa23b04},
    {"LogicGameObjectClient_getZ", 0, "LogicGameObjectClient", 0},
    {"LogicBattleModeClient_getOwnCharacter", 0, "LogicBattleModeClient", 0},
    {"BattleScreen_activateSkill", 0, "BattleScreen", 0},
    {"StringCtor", 1, "String", 0},
    {"Gui_showFloaterTextAtDefaultPos", 0, "Gui", 0},
    {"LogicBattleModeClient_getOwnPlayerTeam", 0, "LogicBattleModeClient", 0},
    {"LogicGameObjectClient_getGlobalID", 0, "LogicGameObjectClient", 0x8},
    {"LogicGameObjectClient_getData", 0, "LogicGameObjectClient", 0x10},
    {"LogicProjectileData_getRadius", 0, "LogicProjectileData", 0},
    {"LogicProjectileData_getSpeed", 0, "LogicProjectileData", 0x124},
    {"LogicProjectileData_getRendering", 0, "LogicProjectileData", 0},
    {"LogicCharacterData_getCollisionRadius", 0, "LogicCharacterData", 0},
    {"decoratedTextFieldSetPlayerName", 1, "DecoratedTextField", 0},
    {"TextField_setText_ui", 0, "TextField", 0},
    {"TextField_setText", 0, "TextField", 0},
    {"handleJoystick", 1, "handleJoystick", 0},
    {"ClientInput_constructor_int", 1, "ClientInput", 0},
    {"ClientInputManager_addInput", 0, "ClientInputManager", 0x74675c},
    {"LogicBattleModeClient_setClientPredictionMoveTo", 0, "LogicBattleModeClient", 0xac3a58},
    {"Sprite_Sprite", 1, "Sprite", 0},
    {"TileMap_Width", 1, "TileMap", 0xc4},
    {"TileMap_Height", 1, "TileMap", 0xc8},
    {"TileMap_TilesArray", 1, "TileMap", 0x20},
    {"TileTypeData_BlocksMovement", 1, "TileTypeData", 0x56},
    {"TileTypeData_BlocksProjectiles", 1, "TileTypeData", 0x57},
    {"LogicTileData__blocksProjectiles", 0, "LogicTileData", 0x57},
    {"BattleMode_objectManagerPtr", 1, "BattleMode", 0x28},
    {"BattleMode_clientInputManager", 1, "BattleMode", 0x58},
    {"ObjectManager_objectsArray", 1, "ObjectManager", 0x0},
    {"ObjectManager_count", 1, "ObjectManager", 0xc},
    {"ObjectManager_ptrStride", 1, "ObjectManager", 0x8},
    {"GameObj_team", 1, "GameObj", 0x40},
    {"LogicGameObjectClient_ownerIndex", 1, "LogicGameObjectClient", 0x3c},
    {"GameObj_deadFlag", 1, "GameObj", 0xd0},
    {"CharData_speed", 1, "CharData", 0x1c4},
    {"CharData_brawlerId", 1, "CharData", 0},
    {"Projectile_isIndirect", 0, "Projectile", 0xb8},
    {"Projectile_angle", 1, "Projectile", 0x1d4},
    {"LogicCharacterClientOwn_speedBuff", 1, "LogicCharacterClientOwn_", 0},
    {"LogicProjectileClient_ownerTeam", 1, "LogicProjectileClient", 0x4c},
    {"LogicProjectileClient_dataName", 1, "LogicProjectileClient", 0x58},
    {"Joy_currentX", 1, "Joy", 0},
    {"Joy_currentY", 1, "Joy", 0},
    {"Joy_centerX", 1, "Joy", 0},
    {"Joy_centerY", 1, "Joy", 0},
    {"Joy_isDragging", 0, "Joy", 0},
    {"ScString_length", 1, "ScString", 0x4},
    {"ScString_data", 1, "ScString", 0x8},
    {"ScString_destruct", 1, "ScString", 0},
    {"ResourceManager__isResourceLoaded", 0, "ResourceManager", 0},
    {"GameMain__update", 0, "GameMain", 0},
    {"DecalManager__DecalManager", 0, "DecalManager", 0},
    {"LogicProjectileData__IsOwnTeamProjectile", 0, "LogicProjectileData", 0},
    {"GameObjectManager__GameObjectManager", 0, "GameObjectManager", 0},
    {"Projectile_ctor", 0, "Projectile", 0},
    {"Projectile__update", 0, "Projectile", 0},
    {"RenderSystem__RenderSystem", 0, "RenderSystem", 0},
    {"CombatHUD__toggleEditing", 0, "CombatHUD", 0},
    {"BattleScreen__updateCameraParameters", 0, "BattleScreen", 0},
    {"Character__updateHealthBar", 0, "Character", 0},
    {"CombatHUD__setShootStickState", 0, "CombatHUD", 0},
    {"CombatHUD__setMoveStickState", 0, "CombatHUD", 0},
    {"GUI__getDefaultFloaterPos", 0, "Gui", 0},
    {"GUI__showFloaterTextAt", 0, "Gui", 0},
    {"GUI__showPopup", 0, "Gui", 0},
    {"GameButtonCtor", 1, "GameButton", 0},
    {"DropGUIContainer__ctorFromExport", 0, "DropGUIContainer", 0},
    {"DropGUIContainer_movieClip", 1, "DropGUIContainer", 0},
    {"GameSliderComponent__GameSliderComponent", 0, "GameSliderComponent", 0},
    {"GameSliderComponent__setValueBounds", 0, "GameSliderComponent", 0},
    {"MapEditorModifierItem__MapEditorModifierItem", 0, "MapEditorModifierItem", 0},
    {"MapEditorModifierPopup__MapEditorModifierPopup", 0, "MapEditorModifierPopup", 0},
    {"MapEditorModifierPopup__addModifierItem", 0, "MapEditorModifierPopup", 0},
    {"PopupBase__PopupBase", 0, "PopupBase", 0},
    {"MessageManager__receiveMessage", 0, "MessageManager", 0},
    {"BattleScreen__BattleScreen", 0, "BattleScreen", 0},
    {"BattleScreen__stopWithStick", 0, "BattleScreen", 0},
    {"BattleScreen__handleTouchReleased", 0, "BattleScreen", 0},
    {"BattleScreen__update", 0, "BattleScreen", 0},
    {"BattleScreen_spectateWidget", 0, "BattleScreen", 0},
    {"BattleScreen_spectateTextField", 0, "BattleScreen", 0},
    {"BattleScreen__updateAutoshoot", 0, "BattleScreen", 0},
    {"BattleScreen_getClosestTargetForAutoshoot", 0, "BattleScreen", 0},
    {"BattleScreen__updateMovement", 0, "BattleScreen", 0x7a60f4},
    {"BattleScreen__tryToActivateSkill", 0, "BattleScreen", 0},
    {"BattleScreen__shouldShowAccessoryButton", 0, "BattleScreen", 0},
    {"BattleScreen__calculateProjectilePath", 0, "BattleScreen", 0},
    {"BattleScreen__joystickToWorld", 0, "BattleScreen", 0},
    {"GameScreen__getLogicBattle", 0, "GameScreen", 0},
    {"MapEditorScreen__initRenderSystem", 0, "MapEditorScreen", 0},
    {"MapEditorScreen__initItems", 0, "MapEditorScreen", 0},
    {"MapEditorScreen__initCharacters", 0, "MapEditorScreen", 0},
    {"GameSettings__isFixedJoystickEnabled", 0, "GameSettings", 0},
    {"BattleMode__enter", 0, "BattleMode", 0},
    {"BattleMode__addResourcesToLoad", 0, "BattleMode", 0},
    {"GameStateManager__getInstance", 0, "GameStateManager", 0},
    {"GameStateManager__isState", 0, "GameStateManager", 0},
    {"HomeMode__getInstance", 0, "HomeMode", 0},
    {"StringTable__getMovieClip", 0, "StringTable", 0},
    {"MovieClipHelper__setTextAndScaleIfNecessary", 0, "MovieClipHelper", 0},
    {"LogicTile__setData", 0, "LogicTile", 0},
    {"LogicTileMap__LogicTileMap", 0, "LogicTileMap", 0},
    {"LogicTileMap__isPlayerLineOfSightClear", 0, "LogicTileMap", 0},
    {"LogicTileMap__isPlayerLineOfSightClear1", 0, "LogicTileMap", 0},
    {"LogicDataTables__getOpenTileData", 0, "LogicDataTables", 0},
    {"LogicDataTables__getBaseTileData", 0, "LogicDataTables", 0},
    {"LogicDataTables__getSiegeBoltTileData", 0, "LogicDataTables", 0},
    {"LogicProjectileData__isBeam", 0, "LogicProjectileData", 0},
    {"LogicCharacterData_getSpeed", 0, "LogicCharacterData", 0},
    {"LogicProjectileData__getNumEarlyTicks", 0, "LogicProjectileData", 0},
    {"LogicSkillData__getActiveTime", 0, "LogicSkillData", 0},
    {"LogicSkillData__getRechargeTime", 0, "LogicSkillData", 0},
    {"LogicSkillData__getMaxCharge", 0, "LogicSkillData", 0},
    {"LogicSkillData__getMsBetweenAttacks", 0, "LogicSkillData", 0xfd4},
    {"LogicSkillData__getCastingRange", 0, "LogicSkillData", 0x90},
    {"LogicTileData__blocksMovement", 0, "LogicTileData", 0x56},
    {"LogicCharacterClient__getCarryableData", 0, "LogicCharacterClient", 0},
    {"LogicCharacterClient__getWeaponSkill", 0, "LogicCharacterClient", 0xc10},
    {"LogicCharacterClient__canMoveAndUseThisSkillSimultaneously", 0, "LogicCharacterClient", 0},
    {"LogicCharacterClient__getLinkedCarryable", 0, "LogicCharacterClient", 0},
    {"LogicCharacterClient__getCurrentActiveOrCastingSkill", 0, "LogicCharacterClient", 0},
    {"LogicCharacterClient__getSkillAt", 0, "LogicCharacterClient", 0},
    {"LogicCharacterClient_hyperActive", 1, "LogicCharacterClient", 0x32e},
    {"LogicCharacterClient_body", 1, "LogicCharacterClient", 0},
    {"LogicSkillClient__getData", 0, "LogicSkillClient", 0},
    {"LogicSkillClient__canActivate", 0, "LogicSkillClient", 0},
    {"LogicSkillData__getBehaviour", 0, "LogicSkillData", 0x3c},
    {"LogicSkillData__getLinkedSkill", 0, "LogicSkillData", 0},
    {"LogicSkillData_kind", 1, "LogicSkillData", 0},
    {"SkillCommandTypeTable", 2, "SkillCommandTypeTable", 0},
    {"ClientInput_skillData", 1, "ClientInput", 0x40},
    {"LogicCharacterClientOwn__clientPredictionPauseMovementForSkillCasting", 0, "LogicCharacterClientOwn_", 0},
    {"LogicCharacterClientOwn__clientPredictionUpdateAttackDirection", 0, "LogicCharacterClientOwn_", 0},
    {"LogicGameObjectManagerClient__LogicGameObjectManagerClient", 0, "LogicGameObjectManagerClient", 0},
    {"LogicGameObjectManagerClient__getGameObjects", 0, "LogicGameObjectManagerClient", 0},
    {"LogicGameObjectManagerClient__findGameObject", 0, "LogicGameObjectManagerClient", 0},
    {"LogicGameObjectServer__getData", 0, "LogicGameObjectServer", 0},
    {"LogicProjectileServer__shootProjectile", 0, "LogicProjectileServer", 0},
    {"LogicProjectileServer__runEarlyTicks", 0, "LogicProjectileServer", 0},
    {"GlobalID__getInstanceID", 0, "GlobalID", 0},
    {"LogicPlayerMap__save", 0, "LogicPlayerMap", 0},
    {"LogicPlayerMapUtil__tileDataToTileCode", 0, "LogicPlayerMapUtil", 0},
    {"AnalyticEvent__AnalyticEvent", 0, "AnalyticEvent", 0},
    {"AnalyticEvent__setString", 0, "AnalyticEvent", 0},
    {"LogicBattleModeClient__LogicBattleModeClient", 0, "LogicBattleModeClient", 0},
    {"LogicBattleModeClient__setRandomSeed", 0, "LogicBattleModeClient", 0},
    {"LogicBattleModeClient__setPlayerAvatar", 0, "LogicBattleModeClient", 0},
    {"LogicBattleModeClient__getOwnPlayerIndex", 0, "LogicBattleModeClient", 0},
    {"LogicBattleModeClient__getTileMap", 0, "LogicBattleModeClient", 0},
    {"SetClientPrediction", 1, "SetClientPrediction", 0xac3a58},
    {"ScrollArea__scrollTo", 0, "ScrollArea", 0},
    {"StringTable_getMovieClip", 0, "StringTable", 0},
    {"DisplayObject__setXY", 0, "DisplayObject", 0},
    {"DisplayObject__removeFromParent", 0, "DisplayObject", 0},
    {"MovieClip__getTextFieldByName", 0, "MovieClip", 0},
    {"Sprite__addChild", 0, "Sprite", 0},
    {"Sprite__addChildAt", 0, "Sprite", 0},
    {"Sprite__removeChild", 0, "Sprite", 0},
    {"ScrollArea__updateBounds", 0, "ScrollArea", 0},
    {"ScrollArea__addContent", 0, "ScrollArea", 0},
    {"ScrollArea__removeAllContent", 0, "ScrollArea", 0},
    {"CSVRow__getIntegerValueAt", 0, "CSVRow", 0xbc7644},
    {"CSVRow__getName", 0, "CSVRow", 0},
    {"CSVRow__getValueAt", 0, "CSVRow", 0},
    {"CSVRow__getBooleanValueAt", 0, "CSVRow", 0},
    {"CSVTable__getColumnIndexByName", 0, "CSVTable", 0xbc75e8},
    {"LogicJSONObject__put", 0, "LogicJSONObject", 0},
    {"LogicRandom__setIteratedRandomSeed", 0, "LogicRandom", 0},
    {"LogicCompressedString__LogicCompressedString", 0, "LogicCompressedString", 0},
    {"LogicLongToCodeConverterUtil__LogicLongToCodeConverterUtil", 0, "LogicLongToCodeConverterUtil", 0},
    {"LogicLongToCodeConverterUtil__convert", 0, "LogicLongToCodeConverterUtil", 0},
    {"LogicLongToCodeConverterUtil__toCode", 0, "LogicLongToCodeConverterUtil", 0},
    {"ResourceListener__addFile", 0, "ResourceListener", 0},
    {"String__format", 0, "String", 0},
    {"FramerateManager__setSegment", 0, "FramerateManager", 0},
    {"FramerateManager__setLimit", 0, "FramerateManager", 0},
    {"FramerateManager_targetFps", 1, "FramerateManager", 0},
    {"Application__copyString", 0, "Application", 0},
    {"HeroData_namePtr", 1, "HeroData", 0},
    {"BattleScreen_aimX", 1, "BattleScreen", 0xe6c},
    {"BattleScreen_aimY", 1, "BattleScreen", 0xe70},
    {"BattleScreen_aimTargetId", 1, "BattleScreen", 0},
    {"BattleScreen_fireWrapperFn", 1, "BattleScreen", 0},
    {"ClientInput_x", 1, "ClientInput", 0x10c},
    {"ClientInput_y", 1, "ClientInput", 0x110},
    {"Message_port", 1, "Message", 0},
    {"Message_ipPtr", 1, "Message", 0},
    {"SockAddr_portHi", 1, "SockAddr", 0},
    {"SockAddr_portLo", 1, "SockAddr", 0},
    {"SockAddr_addr0", 0, "SockAddr", 0},
    {"SockAddr_addr1", 0, "SockAddr", 0},
    {"SockAddr_addr2", 0, "SockAddr", 0},
    {"SockAddr_addr3", 0, "SockAddr", 0},
    {"Stage_addChild", 0, "Stage", 0},
    {"Stage_spriteContainer", 1, "Stage", 0},
    {"Sprite_childCount", 1, "Sprite", 0},
    {"Sprite_childArray", 1, "Sprite", 0},
    {"GameButton_setText", 0, "GameButton", 0},
    {"nativeCopyToClipboard", 1, "nativeCopyToClipboard", 0},
    {"BattleScreen_screenWidth", 1, "BattleScreen", 0},
    {"BattleScreen_screenHeight", 1, "BattleScreen", 0},
    {"BattleScreen_viewMatrix", 1, "BattleScreen", 0},
    {"BattleScreen_cameraMode", 1, "BattleScreen", 0},
    {"ResourceManager__getCSV", 0, "ResourceManager", 0},
    {"VTABLE_PROJECTILE_DATA", 2, "VTABLE", 0xff57b0},
    {"StageInstanceGlobalPtr", 2, "Stage", 0},
    {"MovieClip__gotoAndStopFrameIndex", 0, "MovieClip", 0},
    {"MovieClip_gotoAndStop", 1, "MovieClip", 0},
    {"BattleMode_hashEnabled", 1, "BattleMode", 0x70},
    {"BattleMode_hashKey", 1, "BattleMode", 0x60},
    {"ClientInput_typeConstantTable", 2, "ClientInput", 0xe1e058},
    {"ClientInput_hashInnerMask", 2, "ClientInput", 0xe1bbd0},
    {"ClientInput_hashOuterMask", 2, "ClientInput", 0xe1bbf0},
    {"BattleScreen_autoFireBtnHeld", 1, "BattleScreen", 0},
    {"BattleScreen_attackJoyHeld", 1, "BattleScreen", 0},
    {"BattleScreen_ultiJoyHeld", 1, "BattleScreen", 0},
    {"BattleScreen_movePending", 1, "BattleScreen", 0},
    {"LogicCharacterClient__isImmuneOrUntargetable", 0, "LogicCharacterClient", 0},
    {"operator_new", 2, "operator_new", 0},
    {"TeamChatMessage_messageOffset", 1, "TeamChatMessage", 0},
    {"TeamChatMessage__ctor", 0, "TeamChatMessage", 0},
    {"TeamSetMemberReadyMessage_stateOffset", 1, "TeamSetMemberReadyMessage", 0},
    {"TeamSetMemberReadyMessage__ctor", 0, "TeamSetMemberReadyMessage", 0},
    {"MessageManager_instance", 2, "MessageManager", 0},
    {"MessageManager__sendMessage", 0, "MessageManager", 0},
    {"StartSpectateMessage__ctor", 0, "StartSpectateMessage", 0},
    {"HashTagCodeGenerator__ctor", 0, "HashTagCodeGenerator", 0},
    {"HashTagCodeGenerator__toId", 0, "HashTagCodeGenerator", 0},
    {"Gui_getInstance", 0, "Gui", 0},
    {"PiranhaMessage_ctor", 0, "PiranhaMessage", 0},
    {"LogicSkillData__getProjectileData", 0, "LogicSkillData", 0x8},
    {"Name_setupDecorated", 0, "Name", 0},
    {"Name_applyDecoration", 0, "Name", 0},
    {"LogicDataTables_tableArray", 2, "LogicDataTables", 0},
    {"LogicDataTable_findByName", 0, "LogicDataTable", 0},
    {"GRADIENT_TABLE_INDEX", 2, "GRADIENT", 0},
    {"VTABLE_GRADIENT_DATA", 2, "VTABLE", 0},
    {"VTABLE_DECORATED_TEXT_FIELD", 2, "VTABLE", 0},
    {"VTABLE_TEXT_FIELD", 2, "VTABLE", 0},
    {"DisplayObject_parent", 1, "DisplayObject", 0},
    {"DisplayObject_isMovieClipSlot", 0, "DisplayObject", 0},
    {"DecoratedTextField_marker", 1, "DecoratedTextField", 0},
    {"DecoratedTextField_text", 1, "DecoratedTextField", 0},
    {"DecoratedTextField_gradient", 1, "DecoratedTextField", 0},
    {"AllianceManager__startSpectate", 0, "AllianceManager", 0},
    {"AllianceManager_instance", 2, "AllianceManager", 0},
    {"ClientInputMessage_sendMovement", 0, "ClientInputMessage", 0},
    {"CombatHUD__update", 0, "CombatHUD", 0},
    {"CombatHUD__sendPinCommand", 0, "CombatHUD", 0},
    {"CombatHUD__sendSprayCommand", 0, "CombatHUD", 0},
    {"CustomButton_onButtonPressed", 0, "CustomButton", 0},
    {"DisplayObject_x", 1, "DisplayObject", 0},
    {"DisplayObject_y", 1, "DisplayObject", 0},
    {"DisplayObject_scaleX", 1, "DisplayObject", 0},
    {"DisplayObject_scaleY", 1, "DisplayObject", 0},
    {"DisplayObject_visible", 1, "DisplayObject", 0},
    {"GUI_spriteContainer", 1, "Gui", 0},
    {"HashTagCodeGenerator__dtor", 0, "HashTagCodeGenerator", 0},
    {"HashTagCodeGenerator__isValid", 0, "HashTagCodeGenerator", 0},
    {"LogicGameModeUtil__isTileOnPoisonArea", 0, "LogicGameModeUtil", 0},
    {"LogicTileMap_getTile", 0, "LogicTileMap", 0},
    {"LogicProjectileClient_ctor", 0, "LogicProjectileClient", 0},
    {"LogicProjectileClient_destruct", 1, "LogicProjectileClient", 0},
    {"LogicProjectileClient_getData", 0, "LogicProjectileClient", 0},
    {"LogicProjectileClient_getTargetX", 0, "LogicProjectileClient", 0},
    {"LogicProjectileClient_getTargetY", 0, "LogicProjectileClient", 0},
    {"LogicProjectileData__getSpawnAreaEffect", 0, "LogicProjectileData", 0},
    {"AreaEffectData__getRadius", 0, "AreaEffectData", 0},
    {"AreaEffectData__getActiveTimeMs", 0, "AreaEffectData", 0},
    {"LogicData_getName", 0, "LogicData", 0},
    {"MapEditorScreen__updateCameraParameters", 0, "MapEditorScreen", 0},
    {"MovieClip__getChildClipByName", 0, "MovieClip", 0},
    {"MovieClip__setChildVisible", 0, "MovieClip", 0},
    {"MovieClip_frameCount", 1, "MovieClip", 0},
    {"Screen__getDpiClass", 0, "Screen", 0},
    {"Screen__getHeight", 0, "Screen", 0},
    {"Screen__getWidth", 0, "Screen", 0},
    {"Screen_heightGlobal", 2, "Screen", 0},
    {"Screen_widthGlobal", 2, "Screen", 0},
    {"VTABLE_CHARACTER_DATA", 2, "VTABLE", 0},
};
const size_t kTargetCount = sizeof(kTargets) / sizeof(kTargets[0]);

static void fmt_hex(char *dst, size_t cap, uint64_t v)
{
    snprintf(dst, cap, "0x%llx", (unsigned long long)v);
}

static int hint_score(const Image &img, uint64_t rva)
{
    uint32_t w[4] = {0, 0, 0, 0};
    int score = 0;
    int i = 0;
    for (i = 0; i < 4; i++)
    {
        if (!img.u32(img.base + rva + (uint64_t)i * 4, w[i]))
            return 0;
    }
    if (w[0] == 0xD503237Fu || w[0] == 0xD503233Fu)
        score += 3;
    else if ((w[0] & 0xFFC003FFu) == 0xD10003FFu || (w[0] & 0xFFC003FFu) == 0xA98003FFu ||
             w[0] == 0xA9BF7BFDu || (w[0] & 0xFFC07FFFu) == 0xA9007BFDu)
        score += 2;
    else if ((w[0] & 0x9F00001Fu) == 0x90000000u)
        score += 1;
    if (w[1] == 0xD65F03C0u || w[3] == 0xD65F03C0u)
        score += 1;
    for (i = 0; i < 4; i++)
    {
        const uint32_t a = w[i] & 0xFFu;
        const uint32_t b = (w[i] >> 8) & 0xFFu;
        if (a >= 0x20u && a < 0x7Fu && b >= 0x20u && b < 0x7Fu)
            return 0;
        if ((w[i] == 0) && i == 0)
            return 0;
    }
    return score;
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
        if (t.seed > 0x1000u)
        {
            int score = hint_score(img, t.seed);
            uint32_t w0 = 0;
            uint32_t w1 = 0;
            img.u32(img.base + t.seed, w0);
            img.u32(img.base + t.seed + 4, w1);
            f.src = score >= 2 ? "rva+" : "rva";
            snprintf(buf, sizeof buf, "0x%x 0x%x", w0, w1);
            f.info = buf;
            f.info += score >= 2 ? " prologue" : " nomatch";
            if (score >= 2)
            {
                f.value = t.seed;
                r.by_hint++;
                r.resolved++;
            }
            else
            {
                r.missing++;
            }
            r.items.push_back(f);
            continue;
        }
        f.src = "todo";
        f.info = "0x0";
        code_resolve(img, s, f, r.by_str, r.by_sing);
        if (f.value)
            r.resolved++;
        else
            r.missing++;
        r.items.push_back(f);
    }
    RCL_LOGLN("[find] sym=%zu field=%zu hint=%zu unresolved=%zu symtab=%zu", r.by_sym, r.by_field, r.by_hint, r.missing,
              syms.size());
    return r;
}

} // namespace rcl
