//===- HarnessGenerator.h -- Fuzzing Harness Generator------------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// This file implements a fuzzing harness generator using program slicing.
// Given a target function `a` and its enclosing function `b`, it generates
// a minimal harness by:
// 1. Backward slicing from arguments to `a`
// 2. Forward slicing from return value of `a`
// 3. Generating a sliced version of `b` and fuzzing harness
//
//===-----------------------------------------------------------------------===//

#ifndef HARNESS_GENERATOR_H
#define HARNESS_GENERATOR_H

#include "Graphs/SVFG.h"
#include "Graphs/VFG.h"
#include "SVFIR/SVFIR.h"
#include "SVFIR/SVFType.h"
#include "WPA/Andersen.h"
#include "Util/WorkList.h"
#include <set>
#include <map>
#include <string>

// Forward declarations
namespace llvm
{
class Function;
class Module;
}

namespace SVF
{

class HarnessGenerator
{
public:
    typedef Set<const SVFGNode*> SVFGNodeSet;
    typedef Set<const ICFGNode*> ICFGNodeSet;
    typedef FIFOWorkList<const SVFGNode*> SVFGWorkList;

private:
    SVFIR* pag;                          // Program Assignment Graph
    SVFG* svfg;                          // Sparse Value-Flow Graph
    PointerAnalysis* pta;                // Pointer analysis

    std::string targetFuncName;          // Target function `a` to fuzz
    std::string enclosingFuncName;       // Enclosing function `b`

    const FunObjVar* targetFunc;         // SVF representation of `a`
    const FunObjVar* enclosingFunc;      // SVF representation of `b`
    const CallICFGNode* targetCallSite;  // Call site `call a` in `b`

    SVFGNodeSet backwardSlice;           // Backward slice nodes
    SVFGNodeSet forwardSlice;            // Forward slice nodes
    SVFGNodeSet combinedSlice;           // Union of backward + forward

    Set<const FunObjVar*> calleeFuncs;   // Helper functions called in slice

public:
    HarnessGenerator(SVFIR* _pag, SVFG* _svfg, PointerAnalysis* _pta)
        : pag(_pag), svfg(_svfg), pta(_pta),
          targetFunc(nullptr), enclosingFunc(nullptr), targetCallSite(nullptr)
    {
    }

    /// Set target function name
    void setTargetFunction(const std::string& funcName)
    {
        targetFuncName = funcName;
    }

    /// Set enclosing function name
    void setEnclosingFunction(const std::string& funcName)
    {
        enclosingFuncName = funcName;
    }

    /// Main entry point: generate harness
    bool generateHarness();

    /// Phase 1: Locate call site of target function in enclosing function
    bool locateTargetCallSite();

    /// Phase 2: Compute backward slice from call arguments
    void computeBackwardSlice();

    /// Phase 3: Compute forward slice from return value
    void computeForwardSlice();

    /// Phase 4: Combine slices and extract instructions
    void combineSlices();

    /// Phase 5: Generate output (sliced function + harness)
    void generateOutput(const std::string& outputFile);

    /// Get SVFG from SVF infrastructure
    SVFG* getSVFG() const { return svfg; }

    /// Get PAG
    SVFIR* getPAG() const { return pag; }

private:
    /// Helper: Check if a node belongs to the enclosing function
    bool isInEnclosingFunction(const SVFGNode* node) const;

    /// Helper: Backward traverse from a SVFG node
    void backwardTraverse(const SVFGNode* startNode);

    /// Helper: Forward traverse from a SVFG node
    void forwardTraverse(const SVFGNode* startNode);

    /// Helper: Extract callee functions from call sites in slice
    void extractCalleeFunctions();

    /// Helper: Print slice statistics
    void printSliceStats() const;

    /// Helper: Find SVF function by name
    const FunObjVar* findFunction(const std::string& funcName) const;

    /// Helper: Generate sliced LLVM IR function
    llvm::Function* generateSlicedFunction(llvm::Module* module);
};

} // namespace SVF

#endif // HARNESS_GENERATOR_H
