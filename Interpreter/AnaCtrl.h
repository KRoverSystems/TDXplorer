#ifndef _ANA_CTRL_H
#define _ANA_CTRL_H

#include <linux/types.h>

#include <iostream>
#include <map>
#include <sstream>
#include <fstream>

#include "centralhub.h"

class CAnaCtrl {
    
    VMState *m_VM;
   
   public:
    CThinCtrl *m_Thin;
    std::shared_ptr<CAnalyze> m_Analyze;

    CAnaCtrl(VMState *VM, EveMeta* meta);
    ~CAnaCtrl();

   private:
    
};

#endif
