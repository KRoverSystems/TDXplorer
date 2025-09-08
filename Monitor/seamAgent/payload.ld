SECTIONS
{
        .payload64 0 : {
                seam_agent_bin_start = .;
                build/seam_agent.img.o
                seam_agent_bin_end = .;
        }
}
